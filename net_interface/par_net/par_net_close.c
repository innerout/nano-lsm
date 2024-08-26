#include "par_net_close.h"
#include "par_net.h"
#include <stdlib.h>

struct par_net_close_req {
	uint64_t region_id;
} __attribute__((packed));

struct par_net_close_rep {
	uint32_t status;
	uint32_t string_size;
	uint32_t total_bytes;
} __attribute__((packed));

uint32_t par_net_close_req_calc_size(void)
{
	return sizeof(struct par_net_close_req);
}

size_t par_net_close_rep_calc_size(uint32_t string_size)
{
	return sizeof(struct par_net_close_rep) + string_size;
}

struct par_net_close_req *par_net_close_req_create(uint64_t region_id, char *buffer, size_t *buffer_len)
{
	if (par_net_close_req_calc_size() > *buffer_len)
		return NULL;

	struct par_net_close_req *request = (struct par_net_close_req *)(buffer);
	request->region_id = region_id;

	return request;
}

uint64_t par_net_close_get_region_id(struct par_net_close_req *request)
{
	return request->region_id;
}

struct par_net_close_rep *par_net_close_rep_create(const char *error_message, char *buffer, size_t buffer_len)
{
	uint32_t error_message_size = error_message ? strlen(error_message) + 1 : 0;
	par_net_close_rep_calc_size(error_message_size);

	if (buffer_len < par_net_close_rep_calc_size(error_message_size)) {
		log_warn("Buffer too small to fit a close reply");
		_exit(EXIT_FAILURE);
	}

	struct par_net_close_rep *reply = (struct par_net_close_rep *)buffer;
	char *reply_buffer = (char *)reply;
	reply->status = error_message ? 1 : 0;
	memcpy(&reply_buffer[sizeof(struct par_net_close_rep) + error_message_size], error_message, error_message_size);
	return reply;
}

const char *par_net_close_get_string(struct par_net_close_rep *reply)
{
	return (char *)reply + sizeof(struct par_net_close_req);
}

const char *par_net_close_rep_handle_reply(struct par_net_close_rep *reply)
{
	if (reply->status == 1) {
		log_fatal("Invalid reply status");
		const char *return_string = par_net_close_get_string(reply);
		return return_string;
	}

	return NULL;
}
