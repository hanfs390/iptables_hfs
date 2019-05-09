###############################################################
READY:
/*************************************************************/
	# need the library
		install iptables
		install libiptc
		install libnftnl(dont have; error: iptables who?)
/*************************************************************/
	# install libnftn and iptables
		./start.sh
/*************************************************************/
	# match and target struct
		source: ./iptables/include/linux/netfilter/
		define: ./iptables/include/linux/netfilter_ipv4/ip_tables.h
				./iptables/include/linux/netfilter_ipv6/ip6_tables.h
		for example :
				xt_NFQUEUE.h : the struct of NFQ(netfilter queue)
/*************************************************************/




#################################################################
How to insert rule that you want
/**************************************************************/
1/ change iptables code(function:generate_entry in iptables/iptables.c).
   print the struct ipt_entry, ipt_match_entry, ipt_target_entry
   make and install

2/ use iptables insert rule that you want
   generate the rule according to the log
/**************************************************************/


