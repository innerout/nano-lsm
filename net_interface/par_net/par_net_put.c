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
	return sizeof(struct par_net_put_req) + key_size + value_size;
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

	memcpy(&buffer[sizeof(uint32_t) + sizeof(struct par_net_put_req)], key, key_size);
	memcpy(&buffer[sizeof(uint32_t) + sizeof(struct par_net_put_req) + key_size], value, value_size);

	return request;
}

uint64_t par_net_put_get_region_id(struct par_net_put_req *request)
{
	return request->region_id;
}

uint32_t par_net_put_get_key_size(struct par_net_put_req *request)
{
	return request->key_size;
}

uint32_t par_net_put_get_value_size(struct par_net_put_req *request)
{
	return request->value_size;
}

char *par_net_put_get_key(struct par_net_put_req *request)
{
	return (char *)request + sizeof(struct par_net_put_req);
}

char *par_net_put_get_value(struct par_net_put_req *request)
{
	return (char *)request + sizeof(struct par_net_put_req) + request->key_size;
}
