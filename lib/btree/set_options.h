#pragma once

#include <uthash.h>

enum option_type { LL, STRING };

struct lib_option {
	char *name;
	union {
		char *name;
		unsigned long long count;
	} value;
	enum option_type type;
	UT_hash_handle hh;
};

extern struct lib_option *dboptions;

int parse_options(void);
void check_option(char *option_name, struct lib_option *opt_value);
