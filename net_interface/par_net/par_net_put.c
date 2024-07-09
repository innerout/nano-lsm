#include "par_net_put.h"

size_t par_net_req_calc_size(uint32_t key_size, uint32_t value_size)
{
	return sizeof(struct par_net_put_req) + key_size + value_size;
}

struct par_net_put_req *par_net_put_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer, size_t *buffer_len)
{
	if (par_net_req_calc_size(key_size, value_size) > *buffer_len)
		return NULL;

	struct par_net_put_req *request = (struct par_net_put_req *)buffer;
	request->region_id = region_id;
	request->key_size = key_size;
	request->value_size = value_size;

	memcpy(buffer + sizeof(struct par_net_put_req), key, key_size);
	memcpy(buffer + sizeof(struct par_net_put_req) + key_size, value, value_size);

	return request;
}

char *par_put_req_serialize(struct par_net_put_req *request, size_t *buffer_len)
{
	*buffer_len = par_net_req_calc_size(request->key_size, request->value_size);

	char *buffer = malloc(*buffer_len);
	if (!buffer) {
		*buffer_len = 0;
		return NULL;
	}

	memcpy(buffer, request, sizeof(struct par_net_put_req));

	memcpy(buffer + sizeof(struct par_net_put_req), (char *)request + sizeof(struct par_net_put_req),
	       request->key_size);

	memcpy(buffer + sizeof(struct par_net_put_req) + request->key_size,
	       (char *)request + sizeof(struct par_net_put_req) + request->key_size, request->value_size);

	return buffer;
}

struct par_net_put_req *par_put_req_deserialize(char *buffer, size_t *buffer_len)
{
	if (*buffer_len < sizeof(struct par_net_put_req))
		return NULL;

	struct par_net_put_req *request = (struct par_net_put_req *)malloc(sizeof(struct par_net_put_req));
	if (!request) {
		return NULL;
	}

	memcpy(request, buffer, sizeof(struct par_net_put_req));

	size_t actual_size = par_net_req_calc_size(request->key_size, request->value_size);
	if (*buffer_len < actual_size) {
		//call destroy here
		return NULL;
	}

	char *key = malloc(request->key_size);
	char *value = malloc(request->value_size);
	if (!key || !value) {
		//call destroy here
		return NULL;
	}

	memcpy(key, buffer + sizeof(struct par_net_put_req), request->key_size);
	memcpy(value, buffer + sizeof(struct par_net_put_req) + request->key_size, request->value_size);

	return request;
}

struct __attribute__((packed)) parnet_put_rep {
	uint32_t status;
};
