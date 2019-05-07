#include <stdio.h>
#include "ip6tables_hfs.h"
#include "iptables_hfs.h"

int main()
{
	create_new_chain_iptc("hello"); /* add the hello chain to table 'filter' */
	insert_interface_rule_to_chain("FORWARD", "lo", "hello");
	rule_add_interface("FORWARD", "lo", "hello");/* insert the entry FORWAED to hello */
}

