#include <stdio.h>
#include "ip6tables_hfs.h"
#include "iptables_hfs.h"

int main()
{
	/* iptables -N hello */
//	create_new_chain_iptc("hello"); /* add the hello chain to table 'filter' */
	
	/* iptables -I FORWARD -i lo -j hello */
//	insert_interface_rule_to_chain("FORWARD", "lo", "hello");
//  rule_add_interface("FORWARD", "lo", "hello");/* insert the entry FORWAED to hello */

	/* iptables -I FORWARD -p udp --sport 67 -j NFQUEUE --queue-num 1000 */
	insert_udp_rule_to_nfq("FORWARD", 67, SPORT, 1000);
}

