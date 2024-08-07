#include "par_net_delete.h"
#include "par_net.h"

struct par_net_del_req {
	uint64_t region_id;
	uint32_t key_size;
} __attribute__((packed));

struct par_net_del_rep {
	uint32_t status;
	uint32_t total_bytes;
} __attribute__((packed));

size_t par_net_del_req_calc_size(uint32_t key_size)
{
	return sizeof(struct par_net_del_req) + key_size;
}

size_t par_net_del_rep_calc_size(void)
{
	return sizeof(struct par_net_del_rep);
}

struct par_net_del_req *par_net_del_req_create(uint64_t region_id, uint32_t key_size, const char *key, char *buffer,
					       size_t *buffer_len)
{
	if (par_net_del_req_calc_size(key_size) > *buffer_len)
		return NULL;

	struct par_net_del_req *request = (struct par_net_del_req *)(buffer);
	request->key_size = key_size;
	request->region_id = region_id;

	memcpy(&buffer[sizeof(struct par_net_del_req)], key, key_size);

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

struct par_net_del_rep *par_net_del_rep_create(int status, char *buffer, size_t buffer_len)
{
	if (buffer_len < par_net_del_rep_calc_size()) {
		log_warn("Buffer too small");
		return NULL;
	}
	struct par_net_del_rep *reply = (struct par_net_del_rep *)buffer;

	reply->status = status;
	return reply;
}

bool par_net_del_rep_handle_reply(struct par_net_del_rep *reply)
{
	return 1 != reply->status;
}
