#ifndef _IPTABLES_HFS_H
#define _IPTABLES_HFS_H
enum {
	TARGET_CHAIN,
	TARGET_QUEUE
};
enum {
	SPORT,
	DPORT
};
/**
 * create_new_chain_iptc - create a new chain in 'filter' table.
 * return: 0 success; 1 fail; -1 fail
 */
int create_new_chain_iptc(unsigned char *new_chain_name);
/**
 * insert_interface_rule_to_chain - insert a entry to chain(filter by interface).
 * @chain: the chain name
 * @if_name: the interface name that used to filter
 * @target_name: the target chain name
 */
int insert_interface_rule_to_chain(unsigned char *chain, unsigned char *if_name, unsigned char *target_name);
/* the same as insert_interface_rule_to_chain */
int rule_add_interface(unsigned char *chain_name, unsigned char *if_name, unsigned char *target_name);
/**
 * insert_udp_rule_to_nfq - match udp and target is nfq.
 * @chain: the chain name that you want to insert
 * @port_num: the udp port
 * @port_flags: the type of port; SPORT is src port, DPORT is dst port.
 * @num: the number of netfilter queue
 * return: 0 success; -1 or 1 failed;
 */
int insert_udp_rule_to_nfq(unsigned char *chain, int port_num, int port_flags, int num);
#endif
