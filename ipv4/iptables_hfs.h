#ifndef _IPTABLES_HFS_H
#define _IPTABLES_HFS_H

#define DNS_IPTABLES_SOURCE 					1
#define DNS_IPTABLES_DESTINATION 				2
#define DNS_IPTABLES_ADD						4
#define DNS_IPTABLES_DELTE				 		5
#define DNS_IPTABLES_MAXNAMESIZE	            32
#define DNS_IPTABLES_MAXNAMELEN	            	30
#define DNS_INTERFACE_IN	1
#define DNS_INTERFACE_OUT	2
#define IP_CHAIN_CREATE                          4
#define DNS_IPTABLES_REMOVE 2
#define DNS_IPTABLES_FREE   3
enum{
	DNS_MAC_SOURCE,
	DNS_MAC_DESTINATION
};


struct dns_intf_entry_info {
	char *chain;
	char *intf;
	char *setname;
	char *setflag;
	char *target;
	int port;
	int intf_flag;
};

struct xt_mac_info {
	unsigned char srcaddr[ETH_ALEN];
	unsigned char srcmask[ETH_ALEN];
	unsigned char dstaddr[ETH_ALEN];
	unsigned char dstmask[ETH_ALEN];
	u8 flags;
	u8 srcflags;
	u8 dstflags;
 };

int 
connect_up(const unsigned int user_ip,int domain_id);
int 
connect_down(const unsigned int user_ip,int domain_id);

int dns_iptable_add_interface(char *intf,int domain_id);
int dns_iptable_del_interface(char *intf,int domian_id,int type);
int  dns_add_rule_by_usermac(const u8 *mac, int arp_id);
int  dns_del_rule_by_usermac(const u8 *mac, int arp_id);

int dns_add_iptables_rule_by_arp(char *intf, char *filter_match_name, 
								 char *filter_target_name,
								 char *nat_match_name,
								 char *nat_target_name);

int dns_iptable_del_interface_by_arp(char *intf,char *filter_match_name, 
									char *filter_target_name,
									char *nat_match_name,
									char *nat_target_name,
									int type);

int dns_iptable_flush_all_rules(char *filter_match_name, char *nat_match_name, int type);



#endif
