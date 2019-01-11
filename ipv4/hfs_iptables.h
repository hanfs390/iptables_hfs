#ifndef __HFS_IPTABLES_H
#define __HFS_IPTABLES_H
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include "libiptc/libiptc.h"
#include "iptables.h"

int check_chain_in_tables(const char * table_name,const char * chain_name);

#endif
