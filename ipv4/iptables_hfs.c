#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/xt_NFQUEUE.h>

#include "iptables_hfs.h"

int create_new_chain_iptc(unsigned char *new_chain_name)
{
	struct iptc_handle *handle = NULL;
	int ret = 0;
	handle = iptc_init("filter");
	if (!handle) {
		printf("iptc_init failed! error: %s\n", iptc_strerror(errno));
		return -1;
	}
	if (iptc_is_chain(new_chain_name, handle)) {
		printf("the chain: %s is exist\n", new_chain_name);
		ret = 1;
		goto FREE;
	}
	if (!iptc_create_chain(new_chain_name, handle)) {
		printf("add new chain %s failed\n", new_chain_name);
		ret = 1;
		goto FREE;
	}
	if (!iptc_commit(handle)) {
		printf("commit failed\n");
		ret = 1;
	}
FREE:
	if (handle) {
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}
static struct ipt_entry *fill_fw_by_interface(unsigned char *if_name)
{
	struct ipt_entry *fw = NULL;
	int size = 0;
	size = XT_ALIGN(sizeof(struct ipt_entry));
	fw = (struct ipt_entry *)malloc(size);
	if (!fw) {
		printf("fw malloc failed\n");
		return NULL;
	}
	memset(fw, 0, size);
	
	fw->ip.proto = 0; /* 0 mean all the protocl */
	strcpy(fw->ip.iniface, if_name);
	for(int i = 0; i < strlen(if_name) + 1; i++) {
		fw->ip.iniface_mask[i] = 0xff;
	}
	return fw;
}
static struct ipt_entry *fill_fw_by_protocol(int proto)
{
	struct ipt_entry *fw = NULL;
	int size = 0;
	size = XT_ALIGN(sizeof(struct ipt_entry));
	fw = (struct ipt_entry *)malloc(size);
	if (!fw) {
		printf("fw malloc failed\n");
		return NULL;
	}
	memset(fw, 0, size);
	fw->ip.proto = proto; /* 0 mean all the protocl */
	printf("sizeof fw %d\n", sizeof(struct ipt_entry));	
	printf("ip.proto %d\n", fw->ip.proto);
	printf("ip.flags %d\n", fw->ip.flags);
	printf("ip.invflags %d\n", fw->ip.invflags);
	return fw;
}
static struct ipt_entry_target *fill_target(int flag, unsigned char *target_name, int num)
{
	struct ipt_entry_target *target = NULL;
	struct xt_NFQ_info_v2 nfq;
	int size = 0;

	if (flag < 0)
		return NULL;
	
	if (flag == TARGET_CHAIN) {
		size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(int));
		target = (struct ipt_entry_target *)malloc(size);
		memset(target, 0, size);
	} else if (flag == TARGET_QUEUE) {
		size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(struct xt_NFQ_info_v2));
		target = (struct ipt_entry_target *)malloc(size);
		memset(target, 0, size);
		nfq.queuenum = num;
		nfq.bypass = 1; /* bypass default enable */
		nfq.queues_total = 1;
		memcpy(target->data, &nfq, XT_ALIGN(sizeof(struct xt_NFQ_info_v2)));
		target->u.user.revision = 3;
	}
	if (target == NULL) {
		printf("target malloc failed\n");
		return NULL;
	}

	target->u.target_size = size;
	if (target_name)	
		strcpy(target->u.user.name, target_name);

	return target;
}
static struct ipt_entry_match *fill_match_udp(int port, int flags)
{
	struct ipt_entry_match *match = NULL;
	struct ipt_udp m_udp, *temp = NULL;
	int size = 0;
	if (port < 0)
		return NULL;
	size = XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct ipt_udp));
	match = (struct ipt_entry_match *)malloc(size);
	printf("length %d\n", size);	
	if (!match) {
		printf("match malloc failed\n");
		return NULL;
	}
	memset(match, 0, size);
	/* fill udp */
	if (flags == SPORT) {
		m_udp.spts[0] = port;
		m_udp.spts[1] = port;
		m_udp.dpts[0] = 0;
		m_udp.dpts[1] = 0xffff;
		m_udp.invflags = 0;
	} else if (flags == DPORT) {
		m_udp.spts[0] = 0;
		m_udp.spts[1] = 0xffff;
		m_udp.dpts[0] = port;
		m_udp.dpts[1] = port;
		m_udp.invflags = 0;
	}
	match->u.match_size = size;
	strncpy(match->u.user.name, "udp", 3); /*is it useful?*/
	temp = (struct ipt_udp *)match->data;
	*temp = m_udp;
	return match;
}
static struct ipt_entry *fill_entry(struct ipt_entry *entry, struct ipt_entry_match *match, struct ipt_entry_target *target)
{
	struct ipt_entry *temp = NULL;
	struct ipt_entry *rule = NULL;
	int size = 0;
	int entry_size = 0;
	int match_size = 0;
	int target_size = 0;
	if (entry)
		entry_size = XT_ALIGN(sizeof(struct ipt_entry));
	if (match)
		match_size = match->u.match_size;
	if (target)
		target_size = target->u.target_size;
	size = entry_size + match_size + target_size;

	temp = (void *)malloc(size);
	rule = (struct ipt_entry *)temp;
	if (!temp) {
		printf("entry malloc failed");
		return NULL;
	}
	entry->target_offset = entry_size + match_size;
	entry->next_offset = size;
	if (entry) {
		*temp = *entry;
	}
	if (match) {
		memcpy(temp->elems, (void *)match, match_size);
	}
	if (target) {
		memcpy(temp->elems + match_size, (void *)target, target_size);
	}
#if 0 /* print the whole entry */
	char *t = (char *)rule;
	for (int i = 0; i < rule->next_offset; i++) {
		printf("%02x\n", t[i]);
	}
#endif
	return rule;
}

int insert_udp_rule_to_nfq(unsigned char *chain, int port_num, int port_flags, int num)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct ipt_entry *fw = NULL;
	struct ipt_entry_target *target = NULL;
	struct ipt_entry_match *match = NULL;
	int ret = 0;
	handle = iptc_init("filter");
	if (!handle) {
		printf("iptc_init failed! error: %s\n", iptc_strerror(errno));
		return -1;
	}
	fw = fill_fw_by_protocol(IPPROTO_UDP); /* define in.h for linux */
	if (!fw) {
		printf("get fw failed\n");
		ret = 1;
		goto FREE;
	}
	match = fill_match_udp(port_num, port_flags);
	if (!match) {
		printf("get match failed\n");
		ret = 1;
		goto FREE;
	}
	/* show match */
	printf("match name %s\n", match->u.user.name);
	printf("revision %d\n", match->u.user.revision);
	printf("match size %d\n", match->u.match_size);
	/* end show */

	target = fill_target(TARGET_QUEUE, "NFQUEUE", num);
	if (!target) {
		printf("get target failed\n");
		ret = 1;
		goto FREE;
	}

	entry = fill_entry(fw, match, target);	
	if (!entry) {
		printf("get entry failed\n");
		ret = 1;
		goto FREE;
	}
	printf("the length of entry %d\n", entry->next_offset);
	printf("the length of fw and match %d\n", entry->target_offset);
	if (!iptc_insert_entry(chain, entry, 0, handle)) {
		printf("insert entry failed %s\n", iptc_strerror(errno));
		ret = 1;
		goto FREE;
	}
	if (!iptc_commit(handle)) {
		printf("commit failed %s\n", iptc_strerror(errno));
		ret = 1;
	}
FREE:
	if (entry) {
		free(entry);
		entry = NULL;
	}
	if (match) {
		free(match);
		match = NULL;
	}
	if (target) {
		free(target);
		target = NULL;
	}
	if (fw) {
		free(fw);
		fw = NULL;
	}
	if (handle) {
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}
int insert_interface_rule_to_chain(unsigned char *chain, unsigned char *if_name, unsigned char *target_name)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct ipt_entry *fw = NULL;
	struct ipt_entry_target *target = NULL;
	int ret = 0;
	handle = iptc_init("filter");
	if (!handle) {
		printf("iptc_init failed! error: %s\n", iptc_strerror(errno));
		return -1;
	}
	fw = fill_fw_by_interface(if_name);
	if (!fw) {
		printf("get fw failed\n");
		ret = 1;
		goto FREE;
	}
	
	target = fill_target(TARGET_CHAIN, target_name, 0);
	if (!target) {
		printf("get target failed\n");
		ret = 1;
		goto FREE;
	}

	entry = fill_entry(fw, NULL, target);
	
	if (!entry) {
		printf("get entry failed\n");
		ret = 1;
		goto FREE;
	}
	if (!iptc_insert_entry(chain, entry, 0, handle)) {
		printf("insert entry failed\n");
		ret = 1;
		goto FREE;
	}
	if (!iptc_commit(handle)) {
		printf("commit failed %s\n", iptc_strerror(errno));
		ret = 1;
	}
FREE:
	if (entry) {
		free(entry);
		entry = NULL;
	}
	if (target) {
		free(target);
		target = NULL;
	}
	if (fw) {
		free(fw);
		fw = NULL;
	}
	if (handle) {
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}

int rule_add_interface(unsigned char *chain_name, unsigned char *if_name, unsigned char *target_name)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *p_entry = NULL;
	struct ipt_entry fw;
	int entry_size = 0;
	
	int target_size = 0;
	struct ipt_entry_target *target = NULL;

	int ret = 0;
	handle = iptc_init("filter");
	if (!handle) {
		printf("init failed %s\n", iptc_strerror(errno));
		return -1;
	}
	/* fill the entry */
	memset(&fw, 0, sizeof(fw));
	fw.ip.proto = 0;
	strcpy(fw.ip.iniface, if_name);
	for (int i = 0; i < strlen(if_name) + 1; i++) {
		fw.ip.iniface_mask[i] = 0xff;
	}
	
	target_size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(int));
	target = calloc(1, target_size);
	if (!target) {	
		printf("target calloc failed %s\n", iptc_strerror(errno));
		goto FREE;
	}
	target->u.target_size = target_size;
	strcpy(target->u.user.name, target_name);

	entry_size = XT_ALIGN(sizeof(struct ipt_entry));
	p_entry = malloc(entry_size + target->u.target_size);
	if (!p_entry) {
		printf("entry malloc failed %s\n", iptc_strerror(errno));
		goto FREE;	
	}
	*p_entry = fw;
	p_entry->target_offset = entry_size;
	p_entry->next_offset = entry_size + target->u.target_size;
	p_entry->ip.src.s_addr = 0x0;	
	p_entry->ip.dst.s_addr = 0x0;	
	p_entry->ip.smsk.s_addr = 0x0;
	p_entry->ip.dmsk.s_addr = 0x0;

	memcpy(p_entry->elems, target, target->u.target_size);

	/* insert the entry */
	ret = iptc_insert_entry(chain_name, p_entry, 0, handle);
	if (!ret) {
		printf("insert failed %s\n", iptc_strerror(errno));
		goto FREE;
	}

	/* commit the change */
	ret = iptc_commit(handle);
	if (!ret) {
		printf("commit failed %s\n", iptc_strerror(errno));
	
	}
FREE:
	if (p_entry) {
		free(p_entry);
		p_entry = NULL;
	}
	if (target) {
		free(target);
		target = NULL;
	}
	if (handle) {
		iptc_free(handle);
		handle = NULL;
	}
}
