#include "par_net_delete.h"

struct par_net_del_req {
	uint64_t region_id;
	uint32_t key_size;
} __attribute__((packed));

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

size_t par_net_del_calc_size(uint32_t key_size)
{
	return sizeof(uint32_t) + sizeof(struct par_net_del_req) + key_size;
}

struct par_net_del_req *par_net_del_req_create(uint64_t region_id, uint32_t key_size, const char *key, char *buffer,
					       size_t *buffer_len)
{
	if (par_net_del_calc_size(key_size) > *buffer_len)
		return NULL;

	struct par_net_del_req *request = (struct par_net_del_req *)(buffer + sizeof(uint32_t));
	request->key_size = key_size;
	request->region_id = region_id;

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_del_req), key, key_size);

	return request;
}

char *par_net_del_serialize(struct par_net_del_req *request, size_t *buffer_len)
{
	char *buffer = (char *)request - sizeof(uint32_t);
	return buffer;
}

struct par_net_rep par_net_del_deserialize(char *buffer, size_t *buffer_len)
{
	struct par_net_rep del_rep;
	if (*buffer_len < sizeof(uint32_t) + sizeof(struct par_net_del_req)) {
		del_rep.status = REP_FAIL;
		return del_rep;
	}

	struct par_net_del_req *request = (struct par_net_del_req *)(buffer + sizeof(uint32_t));

	char *key = (char *)malloc(request->key_size);

	memcpy(key, buffer + sizeof(uint32_t) + sizeof(struct par_net_del_req), request->key_size);

	par_handle handle = (par_handle)request->region_id;
	struct par_key *k = malloc(sizeof(struct par_key));

	k->size = request->key_size;
	k->data = key;

	par_delete(handle, k, NULL);

	//Call destroy here

	del_rep.status = REP_SUCCESS;
	return del_rep;
}
