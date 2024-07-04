#include "../allocator/kv_format.h"
#include "../allocator/log_structures.h"
#include "../allocator/persistent_operations.h"
#include "../allocator/region_log.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../btree/set_options.h"
#include "../common/common.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include "../lib/allocator/device_structures.h"
#include "../lib/scanner/scanner_mode.h"
#include "../scanner/scanner.h"

#include <stdarg.h>

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void par_append_data(void *dest, size_t *dest_len, const void *src, size_t src_len);

char *par_serialize_par_db_options(par_db_options *db_options, size_t *ser_len);

char *par_serialize_command(uint32_t command, size_t *ser_len);

char *par_serialize_par_key(struct par_key *key, size_t *ser_len);

char *par_serialize_par_value(struct par_value *value, size_t *ser_len);

char *par_serialize_handle(par_handle handle, size_t *ser_len);
