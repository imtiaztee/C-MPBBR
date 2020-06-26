# C-MPBBR
 Coupled Multipath BBR (C-MPBBR) for multipath TCP
This repository has been created for experimenting the C-MPBBR scheme proposed in "Coupled Multipath BBR (C-MPBBR): A Efficient Congestion Control Algorithm for Multipath TCP" in Linux Kernel. ***The article is under review for publication in IEEE Access***

**#Requirements and Dependencies:** <br />
Please access: include/net/inet_connection_socket.h and set: ICSK_CA_PRIV_SIZE to 12 * sizeof(u64). <br />

**#Instructions:** <br />
*How to Run:* <br />
Just compile and install is as a module.
Change the default Congestion Algorithm to "C-MPBBR"

*Above development was based on the Linux version of 4.9.169.*

********************************************************

Thanks.
Imtiaz Mahmud.

********************************************************
For any inquiry, please contact at imtiaz.tee@gmail.com.
