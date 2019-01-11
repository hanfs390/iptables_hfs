#include "hfs_iptables.h"

/**
 * check_chain_in_tables - check the chain in table exist or not
 * return: -1, error; 0, not find; 1, find
 */
int check_chain_in_tables(const char * table_name,const char * chain_name)
{
	int ret = 1;
	struct iptc_handle *handle = NULL;
	if (NULL == table_name || NULL == chain_name)
	{
		printf("function check_is_chain  error,input error\n");
		return -1;
	}
	handle = iptc_init(table_name);
	if (NULL == handle)
	{
		printf("function check_is_chain  error,can't init iptc handle, table name:%s\n",table_name);
		printf("%s\n", iptc_strerror(errno));
		return -1;
	}
	/**
	 * iptc_is_chain - check the chain exist or not
	 * return: 0, not exist; 1, exist
	 */
	if (!iptc_is_chain(chain_name, handle))
	{
		printf("chain is not exist in the table,chain name:%s,"\
			        "table name:%s\n",chain_name,table_name);
		ret = 0;
	}
	
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}
