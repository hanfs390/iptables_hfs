#include <stdio.h>
#include "ip6tables_hfs.h"
#include "iptables_hfs.h"

int main()
{
	int ret;
	const char * chain = NULL;
	const char * tablename = NULL;
	printf("ipv4\n");
	/* find chain in table */
	if (check_chain_in_tables("filter", "FORWARD") == 1) {
		printf("find it\n");
		return 0;
	}
	printf("not find\n");

}

