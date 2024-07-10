#include "par_net.h"

size_t par_net_del_calc_size(uint32_t key_size)
{
	return sizeof(uint32_t) + sizeof(struct par_net_del_req) + key_size;
}

struct par_net_del_req *par_net_del_req_create(uint64_t region_id, uint32_t key_size, const char *key, char *buffer,
					       size_t *buffer_len)
{
	if (par_net_del_calc_size(key_size) > *buffer_len)
		return NULL;

	uint32_t opcode = OPCODE_DEL;
	buffer[0] = opcode;

	struct par_net_del_req *request = (struct par_net_del_req *)buffer;
	request->key_size = key_size;
	request->region_id = region_id;

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_del_req), key, key_size);

	return request;
}

char *par_net_del_serialize(struct par_net_del_req *request, size_t *buffer_len)
{
	*buffer_len = par_net_del_calc_size(request->key_size);

	char *buffer = malloc(*buffer_len);
	if (!buffer) {
		*buffer_len = 0;
		return NULL;
	}

	uint32_t opcode = OPCODE_DEL;
	buffer[0] = opcode;
	memcpy(buffer + sizeof(uint32_t), request, sizeof(struct par_net_del_req));
	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_del_req),
	       (char *)request + sizeof(struct par_net_del_req), request->key_size);

	return buffer;
}

struct par_net_rep par_net_del_deserialize(char *buffer, size_t *buffer_len)
{
	struct par_net_rep del_rep;
	if (*buffer_len < sizeof(uint32_t) + sizeof(struct par_net_del_req)) {
		del_rep.status = REP_FAIL;
		return del_rep;
	}

	buffer += sizeof(uint32_t);

	struct par_net_del_req *request = (struct par_net_del_req *)malloc(sizeof(struct par_net_del_req));
	if (!request) {
		del_rep.status = REP_FAIL;
		return del_rep;
	}

	memcpy(request, buffer, sizeof(struct par_net_del_req));

	size_t actual_size = par_net_del_calc_size(request->key_size);
	if (*buffer_len < actual_size) {
		//Call destroy here
		del_rep.status = REP_FAIL;
		return del_rep;
	}

	char *key = malloc(request->key_size);
	if (!key) {
		del_rep.status = REP_FAIL;
		return del_rep;
	}

	memcpy(key, buffer + sizeof(uint32_t) + sizeof(struct par_net_del_req), request->key_size);

	par_handle handle = (par_handle)request->region_id;
	struct par_key *k = malloc(sizeof(struct par_key));
	k->size = request->key_size;
	k->data = key;

	par_delete(handle, k, NULL);

	del_rep.status = REP_SUCCESS;

	//Call destroy for k here
	return del_rep;
}
