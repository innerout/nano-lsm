#include "par_net_delete.h"

struct par_net_del_req {
	uint64_t region_id;
	uint32_t key_size;
} __attribute__((packed));

struct par_net_del_rep {
	uint32_t status;
} __attribute__((packed));

size_t par_net_del_req_calc_size(uint32_t key_size)
{
	return sizeof(struct par_net_del_req) + key_size;
}

size_t par_net_del_rep_calc_size()
{
	return sizeof(struct par_net_del_rep);
}

struct par_net_del_req *par_net_del_req_create(uint64_t region_id, uint32_t key_size, const char *key, char *buffer,
					       size_t *buffer_len)
{
	if (par_net_del_req_calc_size(key_size) > *buffer_len)
		return NULL;

	struct par_net_del_req *request = (struct par_net_del_req *)(buffer + sizeof(uint32_t));
	request->key_size = key_size;
	request->region_id = region_id;

	memcpy(&buffer[sizeof(uint32_t) + sizeof(struct par_net_del_req)], key, key_size);

	return request;
}

uint64_t par_net_del_get_region_id(struct par_net_del_req *request)
{
	return request->region_id;
}

uint32_t par_net_del_get_key_size(struct par_net_del_req *request)
{
	return request->key_size;
}

char *par_net_del_get_key(struct par_net_del_req *request)
{
	return (char *)request + sizeof(struct par_net_del_req);
}

struct par_net_del_rep *par_net_del_rep_create(int status, size_t *rep_len)
{
	struct par_net_del_rep *reply = malloc(sizeof(struct par_net_del_rep));
	*rep_len = par_net_del_rep_calc_size();

	reply->status = status;
	return reply;
}

void par_net_del_rep_handle_reply(char *buffer)
{
	struct par_net_del_rep *reply = (struct par_net_del_rep *)buffer;

	if (reply->status == 1) {
		log_fatal("Server reply fail");
		_exit(EXIT_FAILURE);
	}

	return;
}
