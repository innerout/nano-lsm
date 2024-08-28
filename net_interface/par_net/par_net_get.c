#include "par_net_get.h"
#include "par_net.h"

struct par_net_get_req {
	uint64_t region_id;
	uint32_t key_size;
	bool fetch_value;
} __attribute__((packed));

struct par_net_get_rep {
	uint32_t is_found;
	uint32_t value_size;
} __attribute__((packed));

bool par_net_get_req_fetch_value(struct par_net_get_req *request)
{
	return request->fetch_value;
}

size_t par_net_get_req_calc_size(uint32_t key_size)
{
	return sizeof(struct par_net_get_req) + key_size;
}

size_t par_net_get_rep_calc_size(uint32_t value_size)
{
	return sizeof(struct par_net_get_rep) + value_size;
}

struct par_net_get_req *par_net_get_req_create(uint64_t region_id, uint32_t key_size, const char *key, bool fetch_value,
					       char *buffer, size_t *buffer_len)
{
	if (par_net_get_req_calc_size(key_size) > *buffer_len)
		return NULL;

	struct par_net_get_req *request = (struct par_net_get_req *)(buffer);
	request->region_id = region_id;
	request->key_size = key_size;
	request->fetch_value = fetch_value;

	memcpy(&buffer[sizeof(struct par_net_get_req)], key, key_size);
	return request;
}

uint64_t par_net_get_get_region_id(struct par_net_get_req *request)
{
	return request->region_id;
}

uint32_t par_net_get_get_key_size(struct par_net_get_req *request)
{
	return request->key_size;
}

char *par_net_get_get_key(struct par_net_get_req *request)
{
	return (char *)request + sizeof(struct par_net_get_req);
}

struct par_net_get_rep *par_net_get_rep_create(bool is_found, struct par_value *v, char *buffer, size_t buffer_len)
{
	if (buffer_len < par_net_get_rep_calc_size(v->val_size)) {
		log_warn("Sorry buffer too small to fit KV pair");
		return NULL;
	}
	struct par_net_get_rep *reply = (struct par_net_get_rep *)buffer;

	reply->is_found = is_found;
	if (false == is_found)
		return reply;

	reply->value_size = v->val_size;
	char *reply_buffer = (char *)reply;
	memcpy(&reply_buffer[sizeof(struct par_net_get_rep)], v->val_buffer, v->val_size);
	return reply;
}

bool par_net_get_rep_handle_reply(struct par_net_get_rep *reply, struct par_value *value)
{
	if (false == reply->is_found)
		return false;

	if (value->val_buffer && value->val_buffer_size < reply->value_size) {
		log_warn("Buffer too small to fit the value");
		return false;
	}

	value->val_buffer_size = value->val_buffer ? value->val_buffer_size : reply->value_size;
	value->val_buffer = value->val_buffer ? value->val_buffer : calloc(1UL, reply->value_size);
	value->val_size = reply->value_size;

	char *buffer = (char *)reply;
	memcpy(value->val_buffer, &buffer[sizeof(struct par_net_get_rep)], value->val_size);
	return true;
}

bool par_net_get_rep_is_found(struct par_net_get_rep *request)
{
	return request->is_found;
}
