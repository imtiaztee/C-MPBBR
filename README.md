# C-MPBBR
Coupled Multipath BBR (C-MPBBR) for multipath TCP. <br /> <br />
This repository has been created for experimenting the C-MPBBR scheme proposed in "Coupled Multipath BBR (C-MPBBR): A Efficient Congestion Control Algorithm for Multipath TCP" in Linux Kernel. The detail article has been published in IEEE Access. ***Article link:  https://ieeexplore.ieee.org/document/9187831***

**#Requirements and Dependencies:** <br />
Please access: include/net/inet_connection_socket.h and set: ICSK_CA_PRIV_SIZE to 12 * sizeof(u64). <br />

**#Instructions:** <br />
*How to Run:* <br />
Just compile and install is as a module.
Change the default Congestion Algorithm to "C-MPBBR"

*Above development was based on the MPTCP v0.93.4 deployed in Linux kernel version of 4.9.169.*

********************************************************

Thanks and regards. <br />
Dr. Imtiaz Mahmud.

********************************************************
For any inquiry, please contact at imtiaz.tee@gmail.com.
