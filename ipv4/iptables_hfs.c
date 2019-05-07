#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>


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
	printf("size %d", size);
	fw = (struct ipt_entry *)malloc(size);
	if (!fw) {
		printf("fw malloc failed\n");
		return NULL;
	}
	memset(fw, 0, size);
	
	fw->ip.proto = 0; /* all the protocl */
	strcpy(fw->ip.iniface, if_name);
	for(int i = 0; i < strlen(if_name) + 1; i++) {
		fw->ip.iniface_mask[i] = 0xff;
	}
	return fw;
}
static struct ipt_entry_target *fill_target(unsigned char *chain, int flag, unsigned char *target_name, int num)
{
	struct ipt_entry_target *target = NULL;
	int size = 0;

	if (target_name == NULL)
		return NULL;
	if (chain == NULL)
		return NULL;
	if (flag < 0)
		return NULL;
	
	if (flag == TARGET_CHAIN) {
		size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(int));
		target = (struct ipt_entry_target *)malloc(size);
	} else if (flag == TARGET_QUEUE) {
		size = sizeof(struct ipt_entry_target);
		/*???????????????????*/
	}
	if (target == NULL) {
		printf("target malloc failed\n");
		return NULL;
	}

	target->u.target_size = size;
	strcpy(target->u.user.name, target_name);

	return target;
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
	printf("entry_size %d, match_size %d, target_size %d\n", entry_size, match_size, target_size);

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
	return rule;
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
	
	target = fill_target(if_name, TARGET_CHAIN, target_name, 0);
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
