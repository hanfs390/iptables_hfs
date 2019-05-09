#include <stdio.h>
#include <sys/errno.h>
#include "libiptc/libiptc.h"
#include "iptables.h"
int main(void)
{
	struct xtc_handle h;
	const char * chain = NULL;
	const char * tablename = "filter";
	int i = 1;
	h = iptc_init(tablename);
	if (!h) {
		printf("init error\n");
	}
	for (chain=iptc_first_chain(&h);chain;chain=iptc_next_chain(&h)) {
		printf("chain%d=%s\n", i++, chain);
	}
	iptc_free(h);
	return 0;
}

