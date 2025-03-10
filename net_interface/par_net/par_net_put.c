#include "par_net_put.h"
#include "par_net.h"
#include "parallax/structures.h"

struct par_net_put_req {
	uint64_t region_id;
	uint32_t key_size;
	uint32_t value_size;
} __attribute__((packed));

struct par_net_put_rep {
	uint32_t status;
	uint32_t total_bytes;
	struct par_put_metadata op_metadata;
} __attribute__((packed));

size_t par_net_put_req_calc_size(uint32_t key_size, uint32_t value_size)
{
	return sizeof(struct par_net_put_req) + key_size + value_size;
}

size_t par_net_put_rep_calc_size(void)
{
	return sizeof(struct par_net_put_rep);
}

struct par_net_put_req *par_net_put_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer, size_t *buffer_len)
{
	if (par_net_put_req_calc_size(key_size, value_size) > *buffer_len)
		return NULL;

	struct par_net_put_req *request = (struct par_net_put_req *)(buffer);
	request->region_id = region_id;
	request->key_size = key_size;
	request->value_size = value_size;

	memcpy(&buffer[sizeof(struct par_net_put_req)], key, key_size);
	memcpy(&buffer[sizeof(struct par_net_put_req) + key_size], value, value_size);

	// log_debug("Key size %lu", (unsigned long)key_size);
	// log_debug("Value size %lu", (unsigned long)value_size);

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

struct par_net_put_rep *par_net_put_rep_create(int status, struct par_put_metadata metadata, char *buffer,
					       size_t buffer_len)
{
	if (buffer_len < par_net_put_rep_calc_size()) {
		log_warn("Sorry buffer too small buffer is %lu B needs %lu B", buffer_len, par_net_put_rep_calc_size());
		return NULL;
	}
	struct par_net_put_rep *reply = (struct par_net_put_rep *)buffer;

	reply->status = status;
	reply->op_metadata = metadata;
	log_debug("LSN got from put is: %lu", reply->op_metadata.lsn);
	return reply;
}

struct par_put_metadata par_net_put_rep_handle_reply(struct par_net_put_rep *reply)
{
	if (reply->status == 0) {
		log_fatal("Invalid Reply status");
		_exit(EXIT_FAILURE);
	}
	return reply->op_metadata;
}
