#include "ip6tables_hfs.h"

#ifdef HAVE_IPV6
#define USE_THREAD_LOCK		0 /* 0, not use mutex; 1, use mutex */
#define CP_DNSS 		"CP_DNSS"
#define DNSS_DNAT 		"DNSS_DNAT"
#define TARGET_NAME      "ACCEPT"
extern char filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];
extern char nat_filter_name[MAX_IPTABLES_LIST][FILTER_NAME_LENTH];

#if USE_THREAD_LOCK
static pthread_mutex_t dns_ip6tables_glock;
#endif

nmp_mutex_t dns_ip6tables_lock = {-1, ""};

static const char *
inet_ntop4(src, dst, size)
	const u_char *src;
	char *dst;
	size_t size;
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];

	if (SPRINTF((tmp, fmt, src[0], src[1], src[2], src[3])) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}

static const char * ip6addr_str(const char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	u_int words[IN6ADDRSZ / INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp += SPRINTF((tp, "%x", words[i]));
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}

/**
 * check_is_chain_ipv6 - the chain is existed in the table or not
 */
static int 
check_is_chain_ipv6(const char * table_name, const char * chain_name)
{
	int ret = DNS_RETURN_OK;
	struct ip6tc_handle *handle = NULL;
	if (NULL == table_name || NULL == chain_name)
	{
		printf("function check_is_chain error, input error\n");
		return DNS_ERR_INPUT_PARAM_ERR;
	}
	nmp_mutex_lock(&dns_ip6tables_lock);
	handle = ip6tc_init(table_name);
	nmp_mutex_unlock(&dns_ip6tables_lock);
	if (NULL == handle)
	{
		printf(DNSS_INFO, "function check_is_chain error, can't init ip6tc handle,"\
			        "table name:%s\n", table_name);
		ret = DNS_ERR_UNKNOWN;
	}
	else if (!ip6tc_is_chain(chain_name, handle))/*check chain exist*/
	{
		printf(DNSS_DEBUG, "chain is not exist in the table, chain name:%s,"\
			        "table name:%s\n", chain_name, table_name);
		ret = IP_CHAIN_CREATE;
	}
	
	if (NULL != handle)
	{
		ip6tc_free(handle);
		handle = NULL;
	}
	return ret;
}

/**
 * add_and_del_entry_ipv6 - add the ipv6 entry to ip6tables
 */
static int 
add_and_del_entry_ipv6(const char *table_name, const char *chain_name,
							char *source_ip, char *dest_ip,
							const char *target_name, const int type)
{	
	struct ip6t_entry *p_entry = NULL;
	struct ip6t_entry_target *p_target  = NULL;
	struct ip6tc_handle *handle = NULL;
	size_t entry_size = 0;
	size_t target_size = 0;
	size_t match_size = 0;
	size_t all_size = 0;
	int return_ret = DNS_RETURN_OK;
	char addrtxt[DNS_INET6_ADDRSTRLEN + 1];/* string for IPv6 */

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG, "ip6tables add_and_del_entry lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use iptables lock*/
	printf(DNSS_DEBUG, "ip6tables add_and_del_entry lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);

	/* check input */
	if (DNS_IPTABLES_ADD != type && DNS_IPTABLES_DELTE != type)
	{
		printf(DNSS_ERROR, "input error, input: %d\n", type);
		goto return_error;
	}
	if (NULL == table_name || NULL == chain_name || NULL == target_name)
	{
		printf(DNSS_ERROR, "input counter_info is NULL\n");
		goto return_error;
	}
	
	handle = ip6tc_init(table_name);
	if ( NULL == handle)
	{
		printf(DNSS_DEBUG, "ip6tables can't init ip6tc handle, table name: %s\n", table_name);
		goto return_error;
	}

	entry_size = XT_ALIGN(sizeof(struct ip6t_entry));
	match_size = 0;
	target_size = XT_ALIGN(sizeof(struct ip6t_entry_target)) + XT_ALIGN(sizeof(int));
	all_size = target_size + match_size + entry_size;

	p_entry = malloc(all_size);
	memset(p_entry, 0, all_size);

	/* Set tha Entry part of the entry */
	/* set source and destination IP address */

	if (NULL != source_ip)
	{
		memset(p_entry->ipv6.smsk.s6_addr, 0xff, sizeof(p_entry->ipv6.smsk.s6_addr));
		memcpy(p_entry->ipv6.src.s6_addr, source_ip, sizeof(p_entry->ipv6.src.s6_addr));
	}
	if (NULL != dest_ip)
	{
		memset(p_entry->ipv6.dmsk.s6_addr, 0xff, sizeof(p_entry->ipv6.dmsk.s6_addr));
		memcpy(p_entry->ipv6.dst.s6_addr, dest_ip, sizeof(p_entry->ipv6.dst.s6_addr));
	}	
	
	/* Set the port 	(All the port is match) */
	p_entry->ipv6.proto = 0;
	/* Set the size */
	p_entry->target_offset = entry_size + match_size;
	p_entry->next_offset = all_size;

	/* Set the ipt_entry_target part of the entry */
	p_target = (struct ip6t_entry_target*)(p_entry->elems+match_size);
	p_target->u.user.target_size = target_size;
	/* Set the target */
	strcpy(p_target->u.user.name, target_name);
	
	/* add or del */
	if (DNS_IPTABLES_ADD == type)
	{
		/* iptc_append_entry - append is insert in to the last */
		if (!ip6tc_insert_entry(chain_name, p_entry, 0, handle))
		{
			printf(DNSS_ERROR, "add ip6tables error: %d,%s; table: %s, chain: %s, s_ipv6: %s, "\
						"d_ipv6: %s, target: %s, handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						ip6addr_str(source_ip, addrtxt, sizeof(addrtxt)), ip6addr_str(dest_ip, addrtxt, sizeof(addrtxt)), target_name, handle);
			goto return_error;
		}
	}
	else if (DNS_IPTABLES_DELTE == type)
	{
		if (!ip6tc_delete_entry(chain_name, p_entry, NULL, handle))
		{
			printf(DNSS_ERROR,"del ip6tables error: %d, %s; table: %s,chain: %s, s_ipv6: %s,"\
						" d_ipv6: %s, target: %s, handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						ip6addr_str(source_ip, addrtxt, sizeof(addrtxt)), ip6addr_str(dest_ip, addrtxt, sizeof(addrtxt)), target_name, handle);
			goto return_error;
		}
	}
	
	if (!ip6tc_commit(handle))
	{
		printf(DNSS_ERROR,"commit ip6tables error: %d, %s; table: %s,chain: %s, s_ipv6: %s, d_ipv6: %s, target: %s, handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						ip6addr_str(source_ip, addrtxt, sizeof(addrtxt)), ip6addr_str(dest_ip, addrtxt, sizeof(addrtxt)), target_name, handle);
		goto return_error;
	}
	return_ret = DNS_RETURN_OK;
	goto return_line;
	
return_error:
	return_ret = DNS_ERR_UNKNOWN;
	goto return_line;

return_line:
	
	if (NULL != p_entry)
	{
		free(p_entry);
		p_entry = NULL;
	}		
	
	if (NULL != handle)
	{
		ip6tc_free(handle);
		handle = NULL;
	}
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"ip6tables add_and_del_entry unlock\n");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6tables add_and_del_entry unlock\n");	
	return return_ret;	
}

/**
 * connect_up_ipv6 - add the ipv6 to the ip6tables
 */
int 
connect_up_ipv6(char *user_ip, int domain_id)
{	
	/* check input */
	if (domain_id < 0)
	{
		printf(DNSS_ERROR, "connect_down_ipv6 error: error domain id input: %d\n", domain_id);		
		return DNS_ERR_INPUT_PARAM_ERR;
	}

	/* search if the chain is exist */
	if ( DNS_RETURN_OK != check_is_chain_ipv6("filter", filter_name[domain_id]) 
		|| DNS_RETURN_OK != check_is_chain_ipv6("nat", nat_filter_name[domain_id]) )
	{
		printf(DNSS_ERROR, "connect_up_ipv6 error: one or more chain is not exist, chain: %s\n", filter_name[domain_id]);
		return DNS_ERR_UNKNOWN;
	}
	
	/* add the entry */
	if ( DNS_RETURN_OK != add_and_del_entry_ipv6("filter", filter_name[domain_id],
							user_ip, NULL, TARGET_NAME, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK !=  add_and_del_entry_ipv6("filter", filter_name[domain_id], NULL,
							user_ip, TARGET_NAME, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK !=  add_and_del_entry_ipv6("nat", nat_filter_name[domain_id],
							user_ip, NULL, TARGET_NAME, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK !=  add_and_del_entry_ipv6("nat", nat_filter_name[domain_id], NULL,
							 user_ip, TARGET_NAME, DNS_IPTABLES_ADD))
	{
		printf(DNSS_ERROR, "connect_up_ipv6 error: add entry error\n");
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;	
}

/**
 * connect_up_ipv6 - del the ipv6 from the ip6tables
 */
int 
connect_down_ipv6(char *user_ip, int domain_id)
{
	/* check input */
	if (domain_id < 0)
	{
		printf(DNSS_ERROR, "connect_down_ipv6 error: error domain id input: %d\n", domain_id);		
		return DNS_ERR_INPUT_PARAM_ERR;
	}

	/* search if the chain is exist */
	if ( DNS_RETURN_OK != check_is_chain_ipv6("filter", filter_name[domain_id])
		|| DNS_RETURN_OK != check_is_chain_ipv6("nat", nat_filter_name[domain_id]) )
	{
		printf(DNSS_INFO, "connect_down_ipv6 error: one or more chain is not exist, chain: %s\n", filter_name[domain_id]);
		return DNS_ERR_UNKNOWN;
	}
	
	/* del the entry */
	if ( DNS_RETURN_OK != add_and_del_entry_ipv6("filter", filter_name[domain_id],
								user_ip, NULL, TARGET_NAME, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != add_and_del_entry_ipv6("filter", filter_name[domain_id], NULL,
								user_ip, TARGET_NAME, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != add_and_del_entry_ipv6("nat", nat_filter_name[domain_id],
								user_ip, NULL, TARGET_NAME, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != add_and_del_entry_ipv6("nat", nat_filter_name[domain_id], NULL,
							 	user_ip, TARGET_NAME, DNS_IPTABLES_DELTE))
	{
		printf(DNSS_ERROR, "connect_down error: delete entry error\n");
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}
/**
 * parse_iniface_ipv6 - fill the input interface of entry
 */
void parse_iniface_ipv6(const char *str, struct ip6t_entry *fw)
{
	int i = 0;
	strcpy(fw->ipv6.iniface, str);
	for ( i = 0; i < strlen(str) + 1; i++ ) {

		fw->ipv6.iniface_mask[i] = 0xff;
	}
}
/**
 * parse_outiface_ipv6 - fill the output interface of entry
 */
void parse_outiface_ipv6(const char *str, struct ip6t_entry *fw)
{
	int i = 0;
	strcpy(fw->ipv6.outiface, str);
	for ( i = 0; i < strlen(str) + 1; i++ ) {
		
		fw->ipv6.outiface_mask[i] = 0xff;
	}
}

/**
 * dns_match_physdev_ipv6 - fill the info to match
 */
static int dns_match_physdev_ipv6(const int flag, const char *intf,
							struct xt_entry_match *match, size_t size)
{
	match = (struct xt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "physdev");
	
	struct xt_physdev_info *info = (struct xt_physdev_info *)match->data;
	if(flag == DNS_INTERFACE_IN)
	{
                strcpy(info->physindev,intf );
                 memset(info->in_mask, 0xFF, IFNAMSIZ);
                info->bitmask = XT_PHYSDEV_OP_IN;
	}
	else if(flag == DNS_INTERFACE_OUT)
	{
	       strcpy(info->physoutdev,intf );
                 memset(info->out_mask, 0xFF, IFNAMSIZ);
                info->bitmask = XT_PHYSDEV_OP_OUT;
	}

	return 0;	
}							
/**
 * dns_ip6table_entry_new - fill a whole entry by 'entry', 'match', 'target'
 */
struct ip6t_entry *dns_ip6table_entry_new(const struct ip6t_entry *fw, struct ip6t_entry_target *target)
{
	struct ip6t_entry *p_entry;
	size_t size = 0;
	int i = 0;
	printf(DNSS_DEBUG, "%s %d\n", __func__, __LINE__);
	size = XT_ALIGN(sizeof(struct ip6t_entry));

	p_entry = malloc(size + target->u.target_size);
	if (NULL == p_entry) {
		printf(DNSS_ERROR,"malloc error: p_entry = NULL\n");
		return p_entry;
	}

	*p_entry = *fw;	
	p_entry->target_offset = size;
	p_entry->next_offset = size + target->u.target_size;
	memset(p_entry->ipv6.src.s6_addr, 0, sizeof(p_entry->ipv6.src.s6_addr));
	memset(p_entry->ipv6.dst.s6_addr, 0, sizeof(p_entry->ipv6.dst.s6_addr));
	memset(p_entry->ipv6.smsk.s6_addr, 0, sizeof(p_entry->ipv6.smsk.s6_addr));
	memset(p_entry->ipv6.dmsk.s6_addr, 0, sizeof(p_entry->ipv6.dmsk.s6_addr));

	/* fill the target */
	memcpy(p_entry->elems, target, target->u.target_size);
	return p_entry;	
}	
/**
 * dns_add_del_intf_entry_ipv6 - create a ip6tables entry according to 'struct dns_intf_entry_info'
 */	
struct ip6t_entry *dns_add_del_intf_entry_ipv6(struct dns_intf_entry_info *info)
{	
	struct ip6t_entry fw, *p_entry = NULL;
	struct ip6t_entry_target *target = NULL;
	size_t size;

	memset(&fw, 0, sizeof(fw));
		
	/* Fill the part of match */
	
	fw.ipv6.proto = 0;/* add protol filtration: '0' mean the all the protocol */
	/* add interface filtration to 'struct ip6t_entry' */
	if ( info->intf_flag == DNS_INTERFACE_IN && info->intf != NULL ) {
		parse_iniface_ipv6(info->intf, &fw);
		printf(DNSS_DEBUG, "match: iniface\n");
	}
	if ( info->intf_flag == DNS_INTERFACE_OUT && info->intf != NULL ) {
		parse_outiface_ipv6(info->intf, &fw);
		printf(DNSS_DEBUG, "match: outiface\n");
	}

	/* Fill the part of target */
	size= XT_ALIGN(sizeof(struct ip6t_entry_target)) + XT_ALIGN(sizeof(int));
	target = calloc(1, size);
	if (NULL == target) {
		printf(DNSS_ERROR,"calloc target part error\n");
		goto return_error;
	}

	target->u.target_size = size;
	strcpy(target->u.user.name, info->target);

	/* Fill the entry */
	p_entry = dns_ip6table_entry_new(&fw, target);
	goto return_line;
	
return_error:
	p_entry = NULL;
return_line:
	if (NULL != target) {
		free(target);
		target = NULL;
	}
	
	printf(DNSS_DEBUG, "%s %d\n", __func__, __LINE__);
	return p_entry;
}
/**
 * dns_ip6table_add_interface_filter_commit - add the chain 'CP_domain_%d' to tables 'filter'
 */
int dns_ip6table_add_interface_filter_commit( char *intf, int domain_id)
{	
	char cap_auth_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	/*CP_FILTER_AUTH_IF*/
	snprintf(cap_auth_intf_chain, DNS_IPTABLES_MAXNAMELEN, "CP_domain_%d", domain_id);

	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("filter");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("filter", cap_auth_intf_chain))
	{
		/* ip6tables -N $CP_FILTER_AUTH_IF */
		ret = ip6tc_create_chain(cap_auth_intf_chain, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", __func__, cap_auth_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
	}

	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = CP_DNSS;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = cap_auth_intf_chain;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	ret = ip6tc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_insert_entry %s error:%s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;

	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}

return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");

	return ret;
}
/**
 * dns_ip6table_add_interface_nat_commit - add the chain 'DNSS_DNAT_%d' to tables 'nat'
 */
int dns_ip6table_add_interface_nat_commit( char *intf, int domain_id)
{	
	char cap_nat_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	/*CP_FILTER_AUTH_IF*/
	snprintf(cap_nat_intf_chain, DNS_IPTABLES_MAXNAMELEN, "DNSS_DNAT_%d", domain_id);

	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("nat");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("nat", cap_nat_intf_chain))
	{
		/*ip6tables -t nat -N $CP_NAT_AUTH_IF*/
		ret = ip6tc_create_chain(cap_nat_intf_chain, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", __func__, cap_nat_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
	}

	/* ip6tables -t nat -I DNSS_DNAT -m physdev --physdev-in ${CP_IF} -j $CP_NAT_DEFAULT_${CP_IF} */
	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = DNSS_DNAT;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = cap_nat_intf_chain;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	ret = ip6tc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_insert_entry %s error:%s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;

	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}

return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");

	return ret;
}

/**
 * dns_ip6table_add_interface_filter_by_arp - add the chain to table 'filter'
 */
int dns_ip6table_add_interface_filter_by_arp( char *intf, char *target_filter, char *match_filter)
{	
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock( &dns_ip6tables_glock );
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("filter");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("filter", match_filter))
	{
		/* ip6tables -N $CP_FILTER_AUTH_IF */
		ret = ip6tc_create_chain(match_filter, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", 
								__func__, match_filter, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("filter", target_filter))
	{
		/* ip6tables -N $CP_FILTER_AUTH_IF */
		ret = ip6tc_create_chain(target_filter, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", 
								__func__, target_filter, ip6tc_strerror(errno));
			goto return_line;
		}
	}

	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = match_filter;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = target_filter;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	ret = ip6tc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_insert_entry %s error:%s\n",
								__func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;

	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");

	return ret;
}
/**
 * dns_ip6table_add_interface_nat_by_arp - add the chain to table 'nat'
 */
int dns_ip6table_add_interface_nat_by_arp( char *intf, char *target_nat, char *match_nat)
{	
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock( &dns_ip6tables_glock );
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("nat");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("nat", match_nat))
	{
		/*ip6tables -t nat -N $CP_NAT_AUTH_IF*/
		ret = ip6tc_create_chain(match_nat, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", 
								__func__, match_nat, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	if(IP_CHAIN_CREATE == check_is_chain_ipv6("nat", target_nat))
	{
		/*ip6tables -t nat -N $CP_NAT_AUTH_IF*/
		ret = ip6tc_create_chain(target_nat, handle);
		if (!ret) {
			printf(DNSS_ERROR,"%s ip6tc_create_chain %s error:%s\n", 
								__func__, target_nat, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	/* ip6tables -t nat -I CP_DNAT -m physdev --physdev-in ${CP_IF} -j $CP_NAT_DEFAULT_${CP_IF}*/
	memset(&intf_info, 0, sizeof(struct dns_intf_entry_info));
	intf_info.chain = match_nat;
	intf_info.intf = intf;
	intf_info.intf_flag = DNS_INTERFACE_IN;
	intf_info.target = target_nat;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	ret = ip6tc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_insert_entry %s error:%s\n",
								__func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;

	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");

	return ret;
}

/**
 * dns_ip6table_add_interface - add the chain to 'filter' nad 'nat'
 */
int dns_ip6table_add_interface(char *intf, int domain_id)
{
	int ret = 0;
	ret = dns_ip6table_add_interface_filter_commit(intf, domain_id);
	if (!ret) {
		printf(DNSS_ERROR, "%s (filter)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_ip6table_add_interface_nat_commit(intf, domain_id);
	if (!ret) {
		printf(DNSS_ERROR, "%s (nat)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

int dns_add_ip6tables_rule_by_arp(char *intf, char *filter_target, 
								 char *filter_match,
								 char *nat_target,
								 char *nat_match)
{
	int ret = 0;
	ret = dns_ip6table_add_interface_filter_by_arp(intf, filter_target, filter_match);
	if (!ret) {
		printf(DNSS_ERROR, "$s (filter)ret=%d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_ip6table_add_interface_nat_by_arp(intf, nat_target, nat_match);
	if (!ret) {
		printf(DNSS_ERROR, "$s (nat)ret=%d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	return DNS_RETURN_OK;
}

static unsigned char *
ip6table_mask(size_t all_size)
{
	unsigned char *mask;
	mask = calloc(1, all_size);
	if (NULL == mask) {
		printf(DNSS_ERROR,"IPV6: calloc error: mask = NULL\n");
		return NULL;
	}
	memset(mask, 0xFF, all_size);
	return mask;
}

/**
 * dns_ip6table_del_interface_filter_commit - del the chain 'CP_domain_%d' from tables 'filter'
 */
int dns_ip6table_del_interface_filter_commit(char * intf, int domain_id, int type)
{
	char cap_auth_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	/*CP_FILTER_AUTH_IF*/
	snprintf(cap_auth_intf_chain, DNS_IPTABLES_MAXNAMELEN, "CP_domain_%d", domain_id);
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

	printf(DNSS_INFO,"%s %s domian_id %d type %d intf %s\n", __func__, \
				cap_auth_intf_chain, domain_id, type, intf);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock\n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("filter");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	
	/* ip6tables -D $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_AUTH_IF} */
	intf_info.chain = CP_DNSS;
	intf_info.intf_flag= DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_auth_intf_chain;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	mask = ip6table_mask(entry->next_offset);
	ret = ip6tc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_delete_entry %s error:%s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* ip6tables -F ${CP_FILTER_AUTH_IF} */
		ret = ip6tc_flush_entries(cap_auth_intf_chain, handle);
		if (!ret) 
		{
			printf(DNSS_ERROR, "%s ip6tc_flush_entries %s error:%s\n", __func__, cap_auth_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
		
		printf(DNSS_INFO, "ip6tc_delete_chain %s\n", cap_auth_intf_chain);
		/* ip6tables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = ip6tc_delete_chain(cap_auth_intf_chain, handle);
		if (!ret)
		{
			printf(DNSS_ERROR, "%s ip6tc_delete_chain %s error:%s\n", __func__, cap_auth_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR, "%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}
/**
 * dns_ip6table_del_interface_nat_commit - del the chain 'DNSS_DNAT_%d' from tables 'nat' hanfushun
 */
int dns_ip6table_del_interface_nat_commit(char * intf, int domain_id, int type)
{
	char cap_nat_intf_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};	/*CP_FILTER_AUTH_IF*/
	snprintf(cap_nat_intf_chain, DNS_IPTABLES_MAXNAMELEN, "DNSS_DNAT_%d", domain_id);
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

	printf(DNSS_INFO, "%s %s domian_id %d type %d intf %s\n", __func__, \
				cap_nat_intf_chain, domain_id, type, intf);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG, "dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG, "ip6table_lock lock\n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("nat");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	
	/* ip6tables -t nat -D DNSS_DNAT -i ${CP_IF} -j $CP_NAT_DEFAULT */
	intf_info.chain = DNSS_DNAT;
	intf_info.intf_flag= DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_nat_intf_chain;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	mask = ip6table_mask(entry->next_offset);
	ret = ip6tc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_delete_entry %s error:%s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* ip6tables -t nat -F ${CP_NAT_AUTH_IF} */
		ret = ip6tc_flush_entries(cap_nat_intf_chain, handle);
		if (!ret) 
		{
			printf(DNSS_ERROR, "%s ip6tc_flush_entries %s error:%s\n", __func__, cap_nat_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
		
		printf(DNSS_INFO, "ip6tc_delete_chain %s\n", cap_nat_intf_chain);
		/* ip6tables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = ip6tc_delete_chain(cap_nat_intf_chain, handle);
		if (!ret)
		{
			printf(DNSS_ERROR, "%s ip6tc_delete_chain %s error:%s\n", __func__, cap_nat_intf_chain, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR, "%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}

/**
 * dns_ip6table_del_interface_filter_by_arp -  Disconnect chain 'target_filter' and chain 'match_filter' in table 'filter'.
 *									 		  if type is DNS_IPTABLES_FREE, del 'target_filter' in table 'filter'.	
 */
int dns_ip6table_del_interface_filter_by_arp( char * intf, char *target_filter, char *match_filter, int type)
{
	
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

	printf(DNSS_INFO, "%s match_name: %s target_name: %s intf: %s\n", __func__, target_filter, match_filter, intf);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("filter");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	
	/* ip6tables -D $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_AUTH_IF} */
	intf_info.chain = match_filter;
	intf_info.intf_flag= DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = target_filter;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	mask = ip6table_mask(entry->next_offset);
	ret = ip6tc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		printf(DNSS_ERROR,"%s ip6tc_delete_entry %s error:%s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* ip6tables -F ${CP_FILTER_AUTH_IF} */
		ret = ip6tc_flush_entries(target_filter, handle);
		if (!ret) 
		{
			printf(DNSS_ERROR, "%s, ip6tc_flush_entries %s error:%s\n", __func__, target_filter, ip6tc_strerror(errno));
			goto return_line;
		}
		
		printf(DNSS_INFO, "ip6tc_delete_chain %s\n", target_filter);
		/* ip6tables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = ip6tc_delete_chain(target_filter, handle);
		if (!ret)
		{
			printf(DNSS_ERROR, "%s ip6tc_delete_chain %s error:%s\n", target_filter, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR, "%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}
/**
 * dns_ip6table_del_interface_nat_by_arp -  Disconnect chain 'target_nat' and chain 'match_nat' in table 'nat'.								 		if type is DNS_IPTABLES_FREE, del 'target_filter' in table 'filter'.	
 */
int dns_ip6table_del_interface_nat_by_arp( char * intf, char *target_nat, char *match_nat, int type)
{
	
	struct ip6tc_handle *handle = NULL;
	struct ip6t_entry *entry = NULL;
	struct dns_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

	printf(DNSS_INFO, "%s match_name: %s target_name: %s intf: %s\n", __func__, target_nat, match_nat, intf);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("nat");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error:%s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
	
	/* ip6tables -t nat -D CP_DNAT -i ${CP_IF} -j $CP_NAT_DEFAULT */
	intf_info.chain = match_nat;
	intf_info.intf_flag= DNS_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = target_nat;
	entry = dns_add_del_intf_entry_ipv6(&intf_info);
	mask = ip6table_mask(entry->next_offset);
	ret = ip6tc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		printf(DNSS_ERROR, "%s ip6tc_delete_entry %s error: %s\n", __func__, intf_info.chain, ip6tc_strerror(errno));
		goto return_line;
	}
	free(entry);
	entry = NULL;
	free(mask);
	mask = NULL;
	
	if(DNS_IPTABLES_FREE == type)
	{
		/* ip6tables -t nat -F ${CP_NAT_AUTH_IF} */
		ret = ip6tc_flush_entries(target_nat, handle);
		if (!ret) 
		{
			printf(DNSS_ERROR,"%s, ip6tc_flush_entries %s error:%s\n", __func__, target_nat, ip6tc_strerror(errno));
			goto return_line;
		}
		
		printf(DNSS_INFO, "ip6tc_delete_chain %s\n", target_nat);
		/* iptables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = ip6tc_delete_chain(target_nat, handle);
		if (!ret)
		{
			printf(DNSS_ERROR, "%s ip6tc_delete_chain %s error:%s\n", target_nat, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_ERROR, "%s ip6tc_commit:%s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}

/**
 * dns_ip6table_flush_filter_by_arp - free all the rules of the chain 'match_name' in table 'filter'
 *									 if type = DNS_IPTABLES_FREE, del the chain 'match_name' in table 'filter'
 */
int dns_ip6table_flush_filter_by_arp(char *match_name, int type)
{
	struct ip6tc_handle *handle = NULL;
	int ret = 0;
	
	printf(DNSS_INFO,"%s match_name:%s\n", __func__, match_name);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("filter");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error: %s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
		
	/* ip6tables -F ${CP_FILTER_AUTH_IF} */
	ret = ip6tc_flush_entries(match_name, handle);
	if (!ret) 
	{
		printf(DNSS_DEBUG,"%s match_name: %s error: %s\n", __func__, match_name, ip6tc_strerror(errno));
		goto return_line;
	}
	
	printf(DNSS_INFO,"ip6tc_delete_chain %s\n", match_name);
	if(DNS_IPTABLES_FREE == type)
	{
		ret = ip6tc_delete_chain(match_name, handle);
		if (!ret)
		{
			printf(DNSS_ERROR,"%s ip6tc_delete_chain: %s error: %s\n", __func__, match_name, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_DEBUG,"%s ip6tc_commit: %s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}
/**
 * dns_ip6table_flush_nat_by_arp - free all the rules of the chain 'match_name' in table 'nat'
 *								   if type = DNS_IPTABLES_FREE, del the chain 'match_name' in table 'nat'
 */
int dns_ip6table_flush_nat_by_arp(char *match_name, int type)
{
	struct ip6tc_handle *handle = NULL;
	int ret = 0;
	
	printf(DNSS_INFO,"%s match_name:%s\n", __func__, match_name);
#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG,"dns_ip6table_glock lock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"ip6table_lock lock \n");
	nmp_mutex_lock(&dns_ip6tables_lock);
	
	handle = ip6tc_init("nat");
	if (!handle) {
		printf(DNSS_ERROR,"%s ip6tc_init error: %s\n", __func__, ip6tc_strerror(errno));
		goto return_line;
	}
		
	/* ip6tables -t nat -F ${CP_NAT_AUTH_IF} */
	ret = ip6tc_flush_entries(match_name, handle);
	if (!ret) 
	{
		printf(DNSS_DEBUG,"%s match_name: %s error: %s\n", __func__, match_name, ip6tc_strerror(errno));
		goto return_line;
	}
	
	printf(DNSS_INFO,"ip6tc_delete_chain %s\n", match_name);
	if(DNS_IPTABLES_FREE == type)
	{
		/* ip6tables -t nat -X ${CP_NAT_AUTH_IF} */
		ret = ip6tc_delete_chain(match_name, handle);
		if (!ret)
		{
			printf(DNSS_ERROR,"%s ip6tc_delete_chain: %s error: %s\n", __func__, match_name, ip6tc_strerror(errno));
			goto return_line;
		}
	}
	ret = ip6tc_commit(handle);
	if (!ret) {
		printf(DNSS_DEBUG,"%s ip6tc_commit: %s\n", __func__, ip6tc_strerror(errno));
	}
	
return_line:
	if (NULL != handle) {
		ip6tc_free(handle);
		handle = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6table_glock unlock\n");
#endif
	/*use ip6table unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG,"ip6table_lock unlock\n");
	
	return ret;
}


int dns_ip6table_del_interface(char *intf, int domain_id, int type)
{
	int ret = 0;
	ret = dns_ip6table_del_interface_filter_commit(intf, domain_id, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (filter)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_ip6table_del_interface_nat_commit(intf, domain_id, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (nat)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

int dns_ip6table_flush_all_rules(char *filter_match_name, char *nat_match_name, int type)
{
	int ret = 0;
	ret = dns_ip6table_flush_filter_by_arp(filter_match_name, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (filter)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_ip6table_flush_nat_by_arp(nat_match_name, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (nat)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}	
	return DNS_RETURN_OK;
}

int dns_ip6table_del_interface_by_arp(char *intf, char *target_filter, 
									char *match_filter,
									char *target_nat,
									char *match_nat,
									int type)
{
	int ret = 0;
	ret = dns_ip6table_del_interface_filter_by_arp(intf, target_filter, match_filter, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (filter)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}
	ret = dns_ip6table_del_interface_nat_by_arp(intf, target_nat, match_nat, type);
	if (!ret) {
		printf(DNSS_ERROR, "%s (nat)ret = %d\n", __func__, ret);
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}
/**
 * get_index_of_entry_by_mac_ipv6 - the rule is exist in the chain or not
 */
static int 
get_index_of_entry_by_mac_ipv6(	const char * table_name, const char * chain_name,
							const uint8_t *mac, const int type)
{	
	const struct ip6t_entry *p_entry = NULL;
	struct ip6t_entry_match *match = NULL;
	struct xt_mac_info *macinfo = NULL;
	struct ip6tc_handle *handle = NULL;
	unsigned int index = 0;
	
	/* check input */
	if (DNS_IPTABLES_SOURCE != type && DNS_IPTABLES_DESTINATION != type)
	{
		printf(DNSS_ERROR, "input error: %d\n",type);
		return -1;
	}
	
	if (NULL == table_name || NULL == chain_name)
	{
		printf(DNSS_ERROR,"input counter_info is NULL\n");
		return -1;
	}
	
	/* ip6tc handle */
	nmp_mutex_lock(&dns_ip6tables_lock);
	handle = ip6tc_init(table_name);
	nmp_mutex_unlock(&dns_ip6tables_lock);
	if (NULL == handle)
	{
		printf(DNSS_ERROR, "can't init ip6tc handle,table name:%s",table_name);
		return -1;
	}

	/* get rules */
	if (DNS_IPTABLES_SOURCE == type)
	{
		for	(p_entry = ip6tc_first_rule((const char *)chain_name, handle);
			p_entry;
			p_entry = ip6tc_next_rule(p_entry, handle))
		{
			match = (struct ip6t_entry_match *)p_entry->elems;
			index++;
			if (!strcmp(match->u.user.name,"mac"))
			{	
				macinfo = (struct xt_mac_info *)match->data;
				if(!memcmp(macinfo->srcaddr, mac, ETH_ALEN))
					goto find;
			}
		}
	}
	else if (DNS_IPTABLES_DESTINATION == type)
	{
		for	(p_entry = ip6tc_first_rule((const char *)chain_name, handle);
			p_entry;
			p_entry = ip6tc_next_rule(p_entry, handle))
		{
			match = (struct ip6t_entry_match *)p_entry->elems;
			index++;
			if (!strcmp(match->u.user.name,"mac"))
			{				
				macinfo = (struct xt_mac_info *)match->data;
				if(!memcmp(macinfo->dstaddr, mac, ETH_ALEN))
					goto find;
			}
		}

	}
	ip6tc_free(handle);
	handle = NULL;

	return 0;
find:
	ip6tc_free(handle);
	handle = NULL;
	return index;
}
/**
 * dns_add_and_del_mac_entry - add or del the mac entry
 * @table_name: name of ip6tables table
 * @chain_name: the chain which the entry will be insert
 * @mac: the match rule 'mac'
 * @match_type: DNS_MAC_SOURCE or DNS_MAC_DESTINATION
 * @target_name: name of target
 * @type: add or del the entry
 */
static int 
dns_add_and_del_mac_entry_ipv6	(const char *table_name, const char *chain_name,
							const u8 *mac, u8 match_type,
							const char *target_name, const int type)
{
	struct ip6t_entry *p_entry = NULL;
	struct ip6t_entry_target *p_target  = NULL;
	struct ip6t_entry_match *p_match = NULL;
	struct xt_mac_info *mac_info = NULL;
	struct xtc_handle *handle = NULL;
	size_t entry_size = 0;
	size_t target_size = 0;
	size_t match_size = 0;
	size_t all_size = 0;
	int return_ret = DNS_RETURN_OK;
	char mac_str[32] = {0};
	unsigned char *matchmask = NULL;

#if USE_THREAD_LOCK	
	printf(DNSS_DEBUG, "dns_ip6tables_glock glock\n");
	pthread_mutex_lock(&dns_ip6tables_glock);
#endif
	/*use ip6tables lock*/
	printf(DNSS_DEBUG,"dns_ip6tables_lock lock\n");
	nmp_mutex_lock(&dns_ip6tables_lock);

	/* check input */
	if (DNS_IPTABLES_ADD != type && DNS_IPTABLES_DELTE != type)
	{
		printf(DNSS_ERROR,"IPV6: input error,input: %d\n",type);
		goto return_error;
	}

	if (NULL == table_name || NULL == chain_name || NULL == target_name)
	{
		printf(DNSS_ERROR,"IPV6: input counter_info is NULL\n");
		goto return_error;
	}

	handle = ip6tc_init(table_name);
	if ( NULL == handle)
	{
		printf(DNSS_DEBUG,"can't init ip6tc handle, table name:%s",table_name);
		goto return_error;
	}

	entry_size = XT_ALIGN(sizeof(struct ip6t_entry));
	match_size = XT_ALIGN(sizeof(struct ip6t_entry_match)) + XT_ALIGN(sizeof(struct  xt_mac_info));

	target_size = XT_ALIGN(sizeof(struct ip6t_entry_target))+XT_ALIGN(sizeof(int));
	all_size = target_size + match_size + entry_size;

	p_entry = malloc(all_size);
	memset(p_entry, 0, all_size);
	/* Set the proto (it's ALL here) */
	p_entry->ipv6.proto = 0;
	/* Set the size */
	p_entry->target_offset = entry_size + match_size;
	p_entry->next_offset = all_size;

	/* Set the ipt_entry_match part of the entry */
	
	/* set match mac */
	p_match = (struct ip6t_entry_match*)p_entry->elems;
	p_match->u.user.match_size = match_size;
	/* set the portol name */
	strcpy(p_match->u.user.name, "mac");

	/* Set the Match Data of Match part---------------- */

	/* get address */
	mac_info = (struct xt_mac_info*)p_match->data;
	/* Set the port 	(All the port is match) */
	printf(DNSS_INFO,"IPV6: match_type = %d\n",match_type);
	switch(match_type)
 	{
		case DNS_MAC_SOURCE:
			mac_info->flags |= 1 << DNS_MAC_SOURCE; 
			memcpy(mac_info->srcaddr, mac, ETH_ALEN);
			break;
		case DNS_MAC_DESTINATION:
			mac_info->flags |= 1 << DNS_MAC_DESTINATION; 
			memcpy(mac_info->dstaddr, mac, ETH_ALEN);
			break;
		default:
			return 0;
 	}
	/* Set the ipt_entry_target part of the entry */
	
	/* get address */
	p_target = (struct ip6t_entry_target*)(p_entry->elems+match_size);
	p_target->u.user.target_size = target_size;
	/* Set the target */
	strcpy(p_target->u.user.name,target_name);

	mac2str(mac,mac_str,32,':');

	/* add or del */
	if (DNS_IPTABLES_ADD == type)
	{
		/* iptc_append_entry - append is insert in to the last */
		if (!ip6tc_append_entry(chain_name, p_entry, handle))
		{
			printf(DNSS_ERROR, "add ip6tables error: %d,%s; table: %s,chain: %s,mac_str: %s,match_type: %d,"\
						"target: %s,handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						mac_str, match_type, target_name, handle);

			goto return_error;
		}
	}
	else if (DNS_IPTABLES_DELTE == type)
	{
		matchmask = ip6table_mask(p_entry->next_offset);
		if (!ip6tc_delete_entry(chain_name, p_entry, matchmask, handle))
		{
			printf(DNSS_ERROR, "del ip6tables error: %d,%s; table: %s,chain: %s,mac_str: %s,match_type: %d,"\
						"target: %s,handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						mac_str, match_type, target_name, handle);
			goto return_error;
		}
	}

	if (!ip6tc_commit(handle))
	{
		printf(DNSS_ERROR, "commit ip6tables error: %d,%s; table: %s,chain: %s,mac_str: %s,match_type: %d,"\
						"target: %s,handle: %p\n",
						errno, ip6tc_strerror(errno), table_name, chain_name,
						mac_str, match_type, target_name, handle);
		goto return_error;
	}
	
	return_ret = DNS_RETURN_OK;
	goto return_line;

return_error:
	return_ret = DNS_ERR_UNKNOWN;
	goto return_line;

return_line:

	if (NULL != p_entry)
	{
		free(p_entry);
		p_entry = NULL;
	}	

	if (NULL != handle)
	{
		ip6tc_free(handle);
		handle = NULL;
	}
	if (DNS_IPTABLES_DELTE == type && matchmask != NULL)
	{
		free(matchmask);
		matchmask = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock(&dns_ip6tables_glock);
	printf(DNSS_DEBUG,"dns_ip6tables_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&dns_ip6tables_lock);
	printf(DNSS_DEBUG, "dns_ip6tables_lock unlock\n");
	return return_ret;	
}


int dns_add_rule_by_usermac_ipv6(const u8 *mac, int arp_id)
{
	int entry_num = 0;
	char mac_str[32] = {0};
	char cp_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char wl_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char dnss_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char nat_wl_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	
	snprintf(cp_arp_chain, DNS_IPTABLES_MAXNAMESIZE, "CP_ARP_%d", arp_id); 
	snprintf(wl_arp_chain, DNS_IPTABLES_MAXNAMESIZE, "WL_ARP_%d", arp_id); 
	snprintf(dnss_arp_chain,DNS_IPTABLES_MAXNAMESIZE, "DNSS_ARP_%d", arp_id); 
	snprintf(nat_wl_arp_chain,DNS_IPTABLES_MAXNAMESIZE, "NAT_WL_ARP_%d", arp_id);
	
	mac2str(mac, mac_str, 32, ':');
	/* serch if the entry is exist */
	entry_num = get_index_of_entry_by_mac_ipv6("filter", wl_arp_chain, mac, DNS_IPTABLES_SOURCE);
	if ( entry_num < 0 ) 
	{
		printf(DNSS_ERROR, "%s error: input param maybe error!\n", __func__);
		return DNS_ERR_UNKNOWN;
	} 
	else if ( entry_num > 0 ) 
	{
		printf(DNSS_ERROR, "%s error: entry is exist in the chain of table "\
					"\"filter\":user_mac: %s, chain_name: CP_FILTER", __func__, mac_str);
		return DNS_ERR_UNKNOWN;
	}

	/* add the entry */
	if ( DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("filter", wl_arp_chain,
							mac, DNS_MAC_SOURCE, cp_arp_chain, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("filter", wl_arp_chain,
							mac, DNS_MAC_DESTINATION, cp_arp_chain, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("nat", nat_wl_arp_chain,
							mac, DNS_MAC_SOURCE, dnss_arp_chain, DNS_IPTABLES_ADD)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("nat", nat_wl_arp_chain,
							mac, DNS_MAC_DESTINATION, dnss_arp_chain, DNS_IPTABLES_ADD) )
	{
		printf(DNSS_DEBUG,"%s error: add entry error\n", __func__);
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

int dns_del_rule_by_usermac_ipv6(const u8 *mac, int arp_id)
{
	int entry_num = 0;
	char cp_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char wl_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char dnss_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	char nat_wl_arp_chain[DNS_IPTABLES_MAXNAMESIZE] = {0};
	
	snprintf(cp_arp_chain, DNS_IPTABLES_MAXNAMESIZE, "CP_ARP_%d", arp_id); 
	snprintf(wl_arp_chain, DNS_IPTABLES_MAXNAMESIZE, "WL_ARP_%d", arp_id); 
	snprintf(dnss_arp_chain,DNS_IPTABLES_MAXNAMESIZE, "DNSS_ARP_%d", arp_id); 
	snprintf(nat_wl_arp_chain,DNS_IPTABLES_MAXNAMESIZE, "NAT_WL_ARP_%d", arp_id); 

	if ( DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("filter", wl_arp_chain,
							mac, DNS_MAC_SOURCE, cp_arp_chain, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("filter", wl_arp_chain,
							mac, DNS_MAC_DESTINATION, cp_arp_chain, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("nat", nat_wl_arp_chain,
							mac, DNS_MAC_SOURCE, dnss_arp_chain, DNS_IPTABLES_DELTE)
		|| DNS_RETURN_OK != dns_add_and_del_mac_entry_ipv6("nat", nat_wl_arp_chain,
							mac, DNS_MAC_DESTINATION, dnss_arp_chain, DNS_IPTABLES_DELTE))
	{
		printf(DNSS_DEBUG,"%s error, add entry error\n", __func__);
		return DNS_ERR_UNKNOWN;
	}

	return DNS_RETURN_OK;
}

#endif
