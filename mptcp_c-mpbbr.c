/* Multipath Bottleneck Bandwidth and RTT (MPBBR) congestion control
 *
 * MPBBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although MPBBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * MPBBR is described in detail in:
 *   "MPBBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing MPBBR development and testing:
 *   https://groups.google.com/forum/#!forum/mpbbr-dev
 *
 * NOTE: MPBBR *must* be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * since pacing is integral to the MPBBR design and implementation.
 * MPBBR without pacing would not function properly, and may incur unnecessary
 * high packet loss rates.
 */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

#include <net/mptcp.h>
/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define MPBBR_SCALE 8	/* scaling factor for fractions in MPBBR (e.g. gains) */
#define MPBBR_UNIT (1 << MPBBR_SCALE)

/* MPBBR has the following modes for deciding how fast to send: */
enum mpbbr_mode {
	MPBBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	MPBBR_DRAIN,	/* drain any queue created during startup */
	MPBBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	MPBBR_PROBE_RTT,	/* cut cwnd to min to probe min_rtt */
};

/* MPBBR congestion control block */
struct mpbbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for MPBBR_PROBE_RTT mode */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64 cycle_mstamp;  /* time of this cycle phase start */
	u32     mode:3,		     /* current mpbbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		tso_segs_goal:7,     /* segments we want in each skb we send */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a MPBBR_PROBE_RTT round at 4 pkts? */
		unused:5,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_b:5;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */

	u32 stop_multipath_count: 16,
		last_number_of_identical_sf: 8,
		num_of_sf_in_btlneck: 8;
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int mpbbr_bw_rtts = CYCLE_LEN + 2;
/* Window length of min_rtt filter (in sec): */
static const u32 mpbbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at mpbbr_cwnd_min_target in MPBBR_PROBE_RTT mode: */
static const u32 mpbbr_probe_rtt_mode_ms = 200;
/* Skip TSO below the following bandwidth (bits/sec): */
static const int mpbbr_min_tso_rate = 1200000;

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const int mpbbr_high_gain  = MPBBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in MPBBR_DRAIN is calculated to typically drain
 * the queue created in MPBBR_STARTUP in a single round:
 */
static const int mpbbr_drain_gain = MPBBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int mpbbr_cwnd_gain  = MPBBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int mpbbr_pacing_gain[] = {
	MPBBR_UNIT * 5 / 4,	/* probe for more available bw */
	MPBBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	MPBBR_UNIT, MPBBR_UNIT, MPBBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	MPBBR_UNIT, MPBBR_UNIT, MPBBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
static const u32 mpbbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 mpbbr_cwnd_min_target = 4;

/* To estimate if MPBBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 mpbbr_full_bw_thresh = MPBBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 mpbbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 mpbbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 mpbbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 mpbbr_lt_bw_ratio = MPBBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 mpbbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 mpbbr_lt_bw_max_rtts = 48;

/* Do we estimate that STARTUP filled the pipe? */
static bool mpbbr_full_bw_reached(const struct sock *sk)
{
	const struct mpbbr *mpbbr = inet_csk_ca(sk);

	return mpbbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
static u32 mpbbr_max_bw(const struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	return minmax_get(&mpbbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 mpbbr_bw(const struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	return mpbbr->lt_use_bw ? mpbbr->lt_bw : mpbbr_max_bw(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 mpbbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= gain;
	rate >>= MPBBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

/* Convert a MPBBR bw and gain factor to a pacing rate in bytes per second. */
static u32 mpbbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = mpbbr_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
static void mpbbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	if (tp->srtt_us) {		/* any RTT sample yet? */
		rtt_us = max(tp->srtt_us >> 3, 1U);
		mpbbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, rtt_us);
	sk->sk_pacing_rate = mpbbr_bw_to_pacing_rate(sk, bw, mpbbr_high_gain);
}

/* Pace using current bw estimate and a gain factor. In order to help drive the
 * network toward lower queues while maintaining high utilization and low
 * latency, the average pacing rate aims to be slightly (~1%) lower than the
 * estimated bandwidth. This is an important aspect of the design. In this
 * implementation this slightly lower pacing rate is achieved implicitly by not
 * including link-layer headers in the packet size used for the pacing rate.
 */
static void mpbbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	printk("oussama 001");
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 rate = mpbbr_bw_to_pacing_rate(sk, bw, gain);

	if (unlikely(!mpbbr->has_seen_rtt && tp->srtt_us))
		mpbbr_init_pacing_rate_from_rtt(sk);
	if (mpbbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

/* Return count of segments we want in the skbs we send, or 0 for default. */
static u32 mpbbr_tso_segs_goal(struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	return mpbbr->tso_segs_goal;
}

static void mpbbr_set_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 min_segs,segs,bytes;
	bytes = min_t(u32, sk->sk_pacing_rate >> sk->sk_pacing_shift,
		      GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / tp->mss_cache, (sk->sk_pacing_rate) < (mpbbr_min_tso_rate >> 3) ? 1 : 2);

	//min_segs = sk->sk_pacing_rate < (mpbbr_min_tso_rate >> 3) ? 1 : 2;
	mpbbr->tso_segs_goal = min(segs,0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static void mpbbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	if (mpbbr->prev_ca_state < TCP_CA_Recovery && mpbbr->mode != MPBBR_PROBE_RTT)
		mpbbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or MPBBR_PROBE_RTT have temporarily cut cwnd */
		mpbbr->prior_cwnd = max(mpbbr->prior_cwnd, tp->snd_cwnd);
}

static void mpbbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	if (event == CA_EVENT_TX_START && tp->app_limited) {
		mpbbr->idle_restart = 1;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (mpbbr->mode == MPBBR_PROBE_BW)
			mpbbr_set_pacing_rate(sk, mpbbr_bw(sk), MPBBR_UNIT);
	}
}

/* Find target cwnd. Right-size the cwnd based on min RTT and the
 * estimated bottleneck bandwidth:
 *
 * cwnd = bw * min_rtt * gain = BDP * gain
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause MPBBR to under-estimate the rate.
 *
 * To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (mpbbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
static u32 mpbbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	printk("oussama 002");
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(mpbbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * mpbbr->min_rtt_us;

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (((w * gain) >> MPBBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * mpbbr->tso_segs_goal;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;

	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (mpbbr->mode == MPBBR_PROBE_BW && gain > MPBBR_UNIT)
		cwnd += 2;

	return cwnd;
}




/* An optimization in MPBBR to recognize identical bottleneck:
 * this function is called for each ack reception,
 * if returns true for the BW is same for three consecutive events.
 * added/edited by: Imtiaz Mahmud (imtiaz.tee@gmail.com)
 */

static void mpbbr_check_multipath_benefit (struct sock *sk)
{
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *low_sf_tp = tcp_sk(sk);
	struct tcp_sock *best_sf_tp = tcp_sk(sk);
	u32 best_full_bw = 0, best_full_bw_lower_limit = 0, thresold = 40, low_full_bw = 999999999, total_delivery_rate = 0, sf_delivered, sf_count = 0;
	u64 sf_bw = 0;
	s32 sf_t;
	struct mptcp_tcp_sock *mptcp;

	 if (!mpcb)
		return;


	 if (mpbbr->mode == MPBBR_PROBE_BW && mpbbr->cycle_idx == 3)
	 {
			mptcp_for_each_sub(mpcb, mptcp)   //modification
			{
				struct sock *sub_sk = mptcp_to_sock(mptcp);
				struct tcp_sock *sf_tp = tcp_sk(sub_sk);
				struct mpbbr *sf_mpbbr = inet_csk_ca(sub_sk);

				if(mpbbr_bw(sub_sk) == 0)
					continue;


				/* Calculate packets lost and delivered in sampling interval. */
				sf_delivered = sf_tp->delivered - sf_mpbbr->lt_last_delivered;

				/* Find average delivery rate in this sampling interval. */
				sf_t = (s32)( div_u64(tp->delivered_mstamp, USEC_PER_MSEC)- sf_mpbbr->lt_last_stamp);
				if (sf_t > 0 && sf_delivered > 0)
				{	/* interval is less than one jiffy, so wait */
					sf_t = jiffies_to_usecs(sf_t);
					sf_bw = (u64)sf_delivered * BW_UNIT;
					do_div(sf_bw, sf_t);
				}
				total_delivery_rate += (u32) sf_bw;
				sf_count += 1;

				printk("sf_bw = %d; total_delivery_rate = %d; mpbbr_bw(sub_sk) = %d", (u32)sf_bw, total_delivery_rate, mpbbr_bw(sub_sk));

				if (low_full_bw > mpbbr_bw(sub_sk))
				{
					low_full_bw = mpbbr_bw(sub_sk);
					low_sf_tp = sf_tp;
				}

				if(best_full_bw < mpbbr_bw(sub_sk))
				{
					best_full_bw = mpbbr_bw(sub_sk);  // bw of sf
					best_sf_tp = sf_tp;
				}
			}
	 }

	 best_full_bw_lower_limit = best_full_bw - ((best_full_bw*thresold) / 100);

	 if (best_full_bw_lower_limit > total_delivery_rate && mpbbr->num_of_sf_in_btlneck < 2 && sf_count > 1 && best_sf_tp != low_sf_tp)
		 mpbbr->stop_multipath_count += 1;
	 else
		 mpbbr->stop_multipath_count = 0;

	 printk("sf_count = %d, low_full_bw = %d; best_full_bw = %d, total_delivery_rate = %d; mpbbr->stop_multipath_count = %d", sf_count,
			  low_full_bw, best_full_bw, total_delivery_rate, mpbbr->stop_multipath_count);

	 if (mpbbr->stop_multipath_count >= 5 && sf_count > 1 && tp == low_sf_tp) // close low sf
		 {
		 	 printk("\n\n\n\n\n\n\n\n lowest sf is closed");
		 	 mpbbr->stop_multipath_count = 5;
		 	 mptcp_sub_force_close (sk);
		 }
}




 static u16 mpbbr_probe_number_of_sf_in_same_bottleneck (struct sock *sk)
 {
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 number_of_identical_sf = 0, final_number_of_identical_sf = 1;
	u32 max_bw = 0, bw_lower_limit = 0, bw_upper_limit = 0, alpha = 20;

	if (!mpcb)
		return 1;


	max_bw = mpbbr_bw(sk);
	bw_lower_limit = max_bw - ((max_bw*alpha) / 100);
	bw_upper_limit = max_bw + ((max_bw*alpha) / 100);

	//printk("bw = %d; bw_lo_lim = %d; bw_up_lim = %d; calculated = %d\n", max_bw, bw_lower_limit, bw_upper_limit, ((max_bw*alpha) / 100));
	printk("base_bw = %d", max_bw);
	struct mptcp_tcp_sock *mptcp;
	mptcp_for_each_sub(mpcb, mptcp) {     //modification
		struct sock *sub_sk = mptcp_to_sock(mptcp);
		u32 sf_max_bw = mpbbr_bw(sub_sk);

		if(mpbbr_bw(sub_sk) == 0)
			continue;

		printk("sf_bw = %d", sf_max_bw);

		if (sf_max_bw >= bw_lower_limit && sf_max_bw <= bw_upper_limit)
				number_of_identical_sf += 1;
	}
	printk("\n");

	if(number_of_identical_sf > 1 && mpbbr->last_number_of_identical_sf > 1)
		final_number_of_identical_sf = number_of_identical_sf;
	else if(number_of_identical_sf == 1 && mpbbr->last_number_of_identical_sf > 1)
		final_number_of_identical_sf = mpbbr->last_number_of_identical_sf;
	else
		final_number_of_identical_sf = 1;


	if(number_of_identical_sf < 1)
		number_of_identical_sf = 1;

	mpbbr->last_number_of_identical_sf = number_of_identical_sf;

	return final_number_of_identical_sf;
 }


 static u32 mpbbr_check_same_bottleneck (struct sock *sk)
 {
	 printk("oussama 003");
	 struct tcp_sock *tp = tcp_sk(sk);
	 struct mpbbr *mpbbr = inet_csk_ca(sk);
	 struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	 if (!mpcb)
		return 1;

	 if (mpbbr->mode == MPBBR_PROBE_BW && mpbbr->cycle_idx == 3)
	 {
		 mpbbr->num_of_sf_in_btlneck = mpbbr_probe_number_of_sf_in_same_bottleneck (sk);
		 			 printk("mpbbr->num_of_sf_in_btlneck %d last_number_of_identical_sf %d\n", mpbbr->num_of_sf_in_btlneck, mpbbr->last_number_of_identical_sf);
	 }

	 if (mpbbr->mode == MPBBR_PROBE_BW && mpbbr->cycle_idx > 1)
	 {
		 if (mpbbr->num_of_sf_in_btlneck < 1)
			 return 1;
		 else
			{
			 //printk("mpbbr->num_of_sf_in_btlneck %d last_number_of_identical_sf %d\n", mpbbr->num_of_sf_in_btlneck, mpbbr->last_number_of_identical_sf);
			 return mpbbr->num_of_sf_in_btlneck;
		 }
	 }

	 else
		 return 1;
 }



/* An optimization in MPBBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
static bool mpbbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u8 prev_state = mpbbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in mpbbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		mpbbr->packet_conservation = 1;
		mpbbr->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked;
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		mpbbr->restore_cwnd = 1;
		mpbbr->packet_conservation = 0;
	}
	mpbbr->prev_ca_state = state;

	if (mpbbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, mpbbr->prior_cwnd);
		mpbbr->restore_cwnd = 0;
	}

	if (mpbbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
static void mpbbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	if (mpbbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	target_cwnd = mpbbr_target_cwnd(sk, bw, gain);
	if (mpbbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, mpbbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	if (mpbbr->mode == MPBBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tp->snd_cwnd = min(tp->snd_cwnd, mpbbr_cwnd_min_target);
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
static bool mpbbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	bool is_full_length =
		tcp_stamp_us_delta(&tp->delivered_mstamp, &mpbbr->cycle_mstamp) >
		mpbbr->min_rtt_us;
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (mpbbr->pacing_gain == MPBBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = mpbbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (mpbbr->pacing_gain > MPBBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= mpbbr_target_cwnd(sk, bw, mpbbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	return is_full_length ||
		inflight <= mpbbr_target_cwnd(sk, bw, MPBBR_UNIT);
}

static void mpbbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->cycle_idx = (mpbbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	mpbbr->cycle_mstamp = tp->delivered_mstamp;
	mpbbr->pacing_gain = mpbbr->lt_use_bw ? MPBBR_UNIT :
					    mpbbr_pacing_gain[mpbbr->cycle_idx];
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static void mpbbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	if (mpbbr->mode == MPBBR_PROBE_BW && mpbbr_is_next_cycle_phase(sk, rs))
		mpbbr_advance_cycle_phase(sk);
}

static void mpbbr_reset_startup_mode(struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->mode = MPBBR_STARTUP;
	mpbbr->pacing_gain = mpbbr_high_gain;
	mpbbr->cwnd_gain	 = mpbbr_high_gain;
}

static void mpbbr_reset_probe_bw_mode(struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->mode = MPBBR_PROBE_BW;
	mpbbr->pacing_gain = MPBBR_UNIT;
	mpbbr->cwnd_gain = mpbbr_cwnd_gain;
	mpbbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(mpbbr_cycle_rand);
	mpbbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

static void mpbbr_reset_mode(struct sock *sk)
{
	if (!mpbbr_full_bw_reached(sk))
		mpbbr_reset_startup_mode(sk);
	else
		mpbbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
static void mpbbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->lt_last_stamp =  div_u64(tp->delivered_mstamp, USEC_PER_MSEC);
	mpbbr->lt_last_delivered = tp->delivered;
	mpbbr->lt_last_lost = tp->lost;
	mpbbr->lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
static void mpbbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->lt_bw = 0;
	mpbbr->lt_use_bw = 0;
	mpbbr->lt_is_sampling = false;
	mpbbr_reset_lt_bw_sampling_interval(sk);
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static void mpbbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 diff;

	if (mpbbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - mpbbr->lt_bw);
		if ((diff * MPBBR_UNIT <= mpbbr_lt_bw_ratio * mpbbr->lt_bw) ||
		    (mpbbr_rate_bytes_per_sec(sk, diff, MPBBR_UNIT) <=
		     mpbbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			mpbbr->lt_bw = (bw + mpbbr->lt_bw) >> 1;  /* avg 2 intvls */
			mpbbr->lt_use_bw = 1;
			mpbbr->pacing_gain = MPBBR_UNIT;  /* try to avoid drops */
			mpbbr->lt_rtt_cnt = 0;
			return;
		}
	}
	mpbbr->lt_bw = bw;
	mpbbr_reset_lt_bw_sampling_interval(sk);
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). MPBBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
static void mpbbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	s32 t;

	if (mpbbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (mpbbr->mode == MPBBR_PROBE_BW && mpbbr->round_start &&
		    ++mpbbr->lt_rtt_cnt >= mpbbr_lt_bw_max_rtts) {
			mpbbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			mpbbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	if (!mpbbr->lt_is_sampling) {
		if (!rs->losses)
			return;
		mpbbr_reset_lt_bw_sampling_interval(sk);
		mpbbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) {
		mpbbr_reset_lt_bw_sampling(sk);
		return;
	}

	if (mpbbr->round_start)
		mpbbr->lt_rtt_cnt++;	/* count round trips in this interval */
	if (mpbbr->lt_rtt_cnt < mpbbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (mpbbr->lt_rtt_cnt > 4 * mpbbr_lt_intvl_min_rtts) {
		mpbbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - mpbbr->lt_last_lost;
	delivered = tp->delivered - mpbbr->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << MPBBR_SCALE) < mpbbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = (s32)( div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - mpbbr->lt_last_stamp);
	if (t < 1)
		return;		/* interval is less than one jiffy, so wait */
	t = jiffies_to_usecs(t);
	/* Interval long enough for jiffies_to_usecs() to return a bogus 0? */
	if (t < 1) {
		mpbbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	mpbbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
static void mpbbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u64 bw;

	mpbbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, mpbbr->next_rtt_delivered)) {
		mpbbr->next_rtt_delivered = tp->delivered;
		mpbbr->rtt_cnt++;
		mpbbr->round_start = 1;
		mpbbr->packet_conservation = 0;
	}

	mpbbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	if (!rs->is_app_limited || bw >= mpbbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		minmax_running_max(&mpbbr->bw, mpbbr_bw_rtts, mpbbr->rtt_cnt, bw);
	}
}

/* Estimate when the pipe is full, using the change in delivery rate: MPBBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least mpbbr_full_bw_thresh (25%) after mpbbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
static void mpbbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 bw_thresh;

	if (mpbbr_full_bw_reached(sk) || !mpbbr->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)mpbbr->full_bw * mpbbr_full_bw_thresh >> MPBBR_SCALE;
	if (mpbbr_max_bw(sk) >= bw_thresh) {
		mpbbr->full_bw = mpbbr_max_bw(sk);
		mpbbr->full_bw_cnt = 0;
		return;
	}
	++mpbbr->full_bw_cnt;
	mpbbr->full_bw_reached = mpbbr->full_bw_cnt >= mpbbr_full_bw_cnt;
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
static void mpbbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	if (mpbbr->mode == MPBBR_STARTUP && mpbbr_full_bw_reached(sk)) {
		mpbbr->mode = MPBBR_DRAIN;	/* drain queue we created */
		mpbbr->pacing_gain = mpbbr_drain_gain;	/* pace slow to drain */
		mpbbr->cwnd_gain = mpbbr_high_gain;	/* maintain cwnd */
	}	/* fall through to check if in-flight is already small: */
	if (mpbbr->mode == MPBBR_DRAIN &&
	    tcp_packets_in_flight(tcp_sk(sk)) <=
	    mpbbr_target_cwnd(sk, mpbbr_max_bw(sk), MPBBR_UNIT))
		mpbbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

/* The goal of PROBE_RTT mode is to have MPBBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * MPBBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at mpbbr_cwnd_min_target=4 packets.
 * After at least mpbbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. MPBBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
static void mpbbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	filter_expired = after(tcp_time_stamp,
			       mpbbr->min_rtt_stamp + mpbbr_min_rtt_win_sec * HZ);
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us <= mpbbr->min_rtt_us || filter_expired)) {
		mpbbr->min_rtt_us = rs->rtt_us;
		mpbbr->min_rtt_stamp = tcp_time_stamp;
	}

	if (mpbbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !mpbbr->idle_restart && mpbbr->mode != MPBBR_PROBE_RTT) {
		mpbbr->mode = MPBBR_PROBE_RTT;  /* dip, drain queue */
		mpbbr->pacing_gain = MPBBR_UNIT;
		mpbbr->cwnd_gain = MPBBR_UNIT;
		mpbbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		mpbbr->probe_rtt_done_stamp = 0;
	}

	if (mpbbr->mode == MPBBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!mpbbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= mpbbr_cwnd_min_target) {
			mpbbr->probe_rtt_done_stamp = tcp_time_stamp +
				msecs_to_jiffies(mpbbr_probe_rtt_mode_ms);
			mpbbr->probe_rtt_round_done = 0;
			mpbbr->next_rtt_delivered = tp->delivered;
		} else if (mpbbr->probe_rtt_done_stamp) {
			if (mpbbr->round_start)
				mpbbr->probe_rtt_round_done = 1;
			if (mpbbr->probe_rtt_round_done &&
			    after(tcp_time_stamp, mpbbr->probe_rtt_done_stamp)) {
				mpbbr->min_rtt_stamp = tcp_time_stamp;
				mpbbr->restore_cwnd = 1;  /* snap to prior_cwnd */
				mpbbr_reset_mode(sk);
			}
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		mpbbr->idle_restart = 0;
}

static void mpbbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	mpbbr_update_bw(sk, rs);
	mpbbr_update_cycle_phase(sk, rs);
	mpbbr_check_full_bw_reached(sk, rs);
	mpbbr_check_drain(sk, rs);
	mpbbr_update_min_rtt(sk, rs);
}

static void mpbbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);
	u32 bw;

	mpbbr_update_model(sk, rs);

	//mpbbr_check_multipath_benefit (sk);

	bw = mpbbr_bw(sk);

	//bw = bw/mpbbr_check_same_bottleneck (sk);		/*	added for MPBBR by Imtiaz Mahmud (imtiaz.tee@gmail.com)	*/

	mpbbr_set_pacing_rate(sk, bw, mpbbr->pacing_gain);
	mpbbr_set_tso_segs_goal(sk);

	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct tcp_sock *best_sf_tp = tcp_sk(sk);
	struct mptcp_tcp_sock *mptcp;
	u32 best_sf_del;
	u32 best_sf_cwnd;
	mptcp_for_each_sub(mpcb, mptcp)   //modification
			{
				struct sock *sub_sk = mptcp_to_sock(mptcp);
				struct tcp_sock *sf_tp = tcp_sk(sub_sk);
				struct mpbbr *sf_mpbbr = inet_csk_ca(sub_sk);
				u32 best_sf_rtt=9999;
				u32 rtt_best_sf,Rtt;
				if(mpbbr_bw(sub_sk) == 0)
					continue;
				Rtt=sf_tp->snd_cwnd*tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache)/(mpbbr_rate_bytes_per_sec(sk, bw, 1*MPBBR_UNIT)*8);
				if(rtt_best_sf>Rtt) {
				best_sf_rtt=Rtt;
				best_sf_tp=sf_tp;
				best_sf_del=mpbbr_bw(sub_sk);
				best_sf_cwnd=sf_tp->snd_cwnd;
				}
			}

	mpbbr_set_cwnd(sk, rs, rs->acked_sacked, bw, mpbbr->cwnd_gain);
	struct tcp_sock *sf_tp = tcp_sk(sk);
	printk("test1 subflow ");
	if(sf_tp!=best_sf_tp && sf_tp->snd_cwnd>bw*best_sf_cwnd/best_sf_del){ sf_tp->snd_cwnd=bw*best_sf_cwnd/best_sf_del;
	printk("test1 not best subflow");

}
}

static void mpbbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->prior_cwnd = 0;
	mpbbr->tso_segs_goal = 0;	 /* default segs per skb until first ACK */
	mpbbr->rtt_cnt = 0;
	mpbbr->next_rtt_delivered = 0;
	mpbbr->prev_ca_state = TCP_CA_Open;
	mpbbr->packet_conservation = 0;

	mpbbr->last_number_of_identical_sf = 1;
	mpbbr->num_of_sf_in_btlneck = 1;
	mpbbr->stop_multipath_count = 0;



	mpbbr->probe_rtt_done_stamp = 0;
	mpbbr->probe_rtt_round_done = 0;
	mpbbr->min_rtt_us = tcp_min_rtt(tp);
	mpbbr->min_rtt_stamp = tcp_time_stamp;

	minmax_reset(&mpbbr->bw, mpbbr->rtt_cnt, 0);  /* init max bw to 0 */

	mpbbr->has_seen_rtt = 0;
	mpbbr_init_pacing_rate_from_rtt(sk);

	mpbbr->restore_cwnd = 0;
	mpbbr->round_start = 0;
	mpbbr->idle_restart = 0;
	mpbbr->full_bw_reached = 0;
	mpbbr->full_bw = 0;
	mpbbr->full_bw_cnt = 0;
	mpbbr->cycle_mstamp = 0;
	mpbbr->cycle_idx = 0;
	mpbbr_reset_lt_bw_sampling(sk);
	mpbbr_reset_startup_mode(sk);
}

static u32 mpbbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since MPBBR may slow-start even during recovery. */
	return 3;
}

/* In theory MPBBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see mpbbr_main()). Keep it for now.
 */
static u32 mpbbr_undo_cwnd(struct sock *sk)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	mpbbr->full_bw = 0;   /* spurious slow-down; reset full pipe detection */
	mpbbr->full_bw_cnt = 0;
	mpbbr_reset_lt_bw_sampling(sk);
	return tcp_sk(sk)->snd_cwnd;
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
static u32 mpbbr_ssthresh(struct sock *sk)
{
	mpbbr_save_cwnd(sk);
	return TCP_INFINITE_SSTHRESH;	 /* MPBBR does not use ssthresh */
}

/*static size_t mpbbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_MPBBRINFO - 1))||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct mpbbr *mpbbr = inet_csk_ca(sk);
		u64 bw = mpbbr_bw(sk);
		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->mpbbr, 0, sizeof(info->mpbbr));
		info->mpbbr.mpbbr_bw_lo		= (u32)bw;
		info->mpbbr.mpbbr_bw_hi		= (u32)(bw >> 32);
		info->mpbbr.mpbbr_min_rtt		= mpbbr->min_rtt_us;
		info->mpbbr.mpbbr_pacing_gain	= mpbbr->pacing_gain;
		info->mpbbr.mpbbr_cwnd_gain		= mpbbr->cwnd_gain;
		*attr = INET_DIAG_MPBBRINFO;
		return sizeof(info->mpbbr);
	}
	return 0;
}*/

static void mpbbr_set_state(struct sock *sk, u8 new_state)
{
	struct mpbbr *mpbbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		mpbbr->prev_ca_state = TCP_CA_Loss;
		mpbbr->full_bw = 0;
		mpbbr->round_start = 1;	/* treat RTO like end of a round */
		mpbbr_lt_bw_sampling(sk, &rs);
	}
}

static struct tcp_congestion_ops tcp_mpbbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "C-MPBBR",
	.owner		= THIS_MODULE,
	.init		= mpbbr_init,
	.cong_control	= mpbbr_main,
	.sndbuf_expand	= mpbbr_sndbuf_expand,
	.undo_cwnd	= mpbbr_undo_cwnd,
	.cwnd_event	= mpbbr_cwnd_event,
	.ssthresh	= mpbbr_ssthresh,
	.min_tso_segs	= mpbbr_tso_segs_goal,
	.get_info	= 0,
	.set_state	= mpbbr_set_state,
};

static int __init mpbbr_register(void)
{
	//BUILD_BUG_ON(sizeof(struct mpbbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_mpbbr_cong_ops);
}

static void __exit mpbbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_mpbbr_cong_ops);
}

module_init(mpbbr_register);
module_exit(mpbbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_AUTHOR("Imtiaz Mahmud <imtiaz.tee@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP MPBBR (Bottleneck Bandwidth and RTT)");
