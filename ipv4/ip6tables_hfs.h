#ifndef _IP6TABLES_HFS_H
#define _IP6TABLES_HFS_H
/**
 * Head File
 */
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/netfilter/nf_nat.h>
#include <pthread.h>
#include <syslog.h>
#include <netdb.h>
#ifndef IFNAMSIZ
	#define IFNAMSIZ 16
#endif
#include <linux/netfilter/xt_iprange.h> 	/* -m iprange */
#include <linux/netfilter/xt_multiport.h>	/* -m multiport */
#include <linux/netfilter/xt_string.h>	/* -m string */
#include <linux/netfilter/xt_comment.h>	/* -m comment */
#include <linux/netfilter/x_tables.h>	/* -m comment */
#include <linux/netfilter/xt_physdev.h>  /*-m physdev*/

/* ip6t_entry is defined in ip6_tables.h */
#define DNS_INET6_ADDRSTRLEN	(48)
#define	IN6ADDRSZ	16
#define	INT16SZ		2
#define SPRINTF(x) ((size_t)sprintf x)
#define ETH_ALEN 6
typedef unsigned char u8;
static const char * ip6addr_str(const char *src, char *dst, size_t size);
int connect_up_ipv6(char *user_ip, int domain_id);
int connect_down_ipv6(char *user_ip, int domain_id);
int dns_ip6table_add_interface(char *intf, int domain_id);
int dns_ip6table_del_interface(char *intf, int domian_id, int type);
int dns_add_rule_by_usermac_ipv6(const u8 *mac, int arp_id);
int dns_del_rule_by_usermac_ipv6(const u8 *mac, int arp_id);
int dns_add_ip6tables_rule_by_arp(char *intf, char *filter_target, 
								 char *filter_match,
								 char *nat_target,
								 char *nat_match);
int dns_ip6table_del_interface_by_arp(char *intf, char *target_filter, 
									char *match_filter,
									char *target_nat,
									char *match_nat,
									int type);
int dns_ip6table_flush_all_rules(char *filter_match_name, char *nat_match_name, int type);
#endif

