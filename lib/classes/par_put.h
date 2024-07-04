#include "../allocator/kv_format.h"
#include "../allocator/log_structures.h"
#include "../allocator/region_log.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../btree/set_options.h"
#include "../common/common.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include "../scanner/scanner.h"
#include "../serializer/deserializer.h"
#include "../serializer/serializer.h"

#include <stdarg.h>

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct par_put_class {
	par_handle handle;
	struct par_key_value *kv;
	const char **error_message;
	char *stream;
	size_t stream_len;

	void (*init)(struct par_put_class *obj, par_handle handle, struct par_key_value *kv);
	void (*serialize)(struct par_put_class *obj);
	void (*send)(struct par_put_class *obj);
};

void par_put_init(struct par_put_class *obj, par_handle handle, struct par_key_value *kv);

void par_put_serialize(struct par_put_class *obj);

void par_put_send(struct par_put_class *obj);
