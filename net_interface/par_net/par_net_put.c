#include "par_net_put.h"

struct par_net_put_req {
	uint64_t region_id;
	uint32_t key_size;
	uint32_t value_size;
} __attribute__((packed));

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

size_t par_net_put_calc_size(uint32_t key_size, uint32_t value_size)
{
	return sizeof(uint32_t) + sizeof(struct par_net_put_req) + key_size + value_size;
}

struct par_net_put_req *par_net_put_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer, size_t *buffer_len)
{
	if (par_net_put_calc_size(key_size, value_size) > *buffer_len)
		return NULL;

	struct par_net_put_req *request = (struct par_net_put_req *)(buffer + sizeof(uint32_t));
	request->region_id = region_id;
	request->key_size = key_size;
	request->value_size = value_size;

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_put_req), key, key_size);
	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_put_req) + key_size, value, value_size);

	return request;
}

char *par_net_put_serialize(struct par_net_put_req *request, size_t *buffer_len)
{
	char *buffer = (char *)request - sizeof(uint32_t);
	return buffer;
}

struct par_net_rep par_net_put_deserialize(char *buffer, size_t *buffer_len)
{
	struct par_net_rep put_reply;

	if (*buffer_len < sizeof(struct par_net_put_req)) {
		put_reply.status = REP_FAIL;
		return put_reply;
	}

	struct par_net_put_req *request = (struct par_net_put_req *)(buffer + sizeof(uint32_t));

	char *key = (char *)malloc(request->key_size);
	char *value = (char *)malloc(request->value_size);

	memcpy(key, buffer + sizeof(uint32_t) + sizeof(struct par_net_put_req), request->key_size);
	memcpy(value, buffer + sizeof(uint32_t) + sizeof(struct par_net_put_req) + request->key_size,
	       request->value_size);

	par_handle handle = &(request->region_id);
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));
	kv->k.size = request->key_size;
	kv->k.data = key;

	kv->v.val_size = request->value_size;
	kv->v.val_buffer_size = request->value_size;
	kv->v.val_buffer = value;

	par_put(handle, kv, NULL);

	//Call destroy here

	put_reply.status = PAR_SUCCESS;
	return put_reply;
}
