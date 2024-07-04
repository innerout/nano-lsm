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

#define MAX_OPCODE_NUM 2

typedef void (*Par_deserialize)(char *stream);

void par_des_init(char *stream, size_t message_len);
void par_des_open(char *stream);
void par_des_put(char *stream);
void par_des_get(char *stream);
void par_des_error(char *stream);

uint32_t par_des_opcode(char *stream);
