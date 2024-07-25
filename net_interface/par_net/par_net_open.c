#include "par_net_open.h"

struct par_net_open_req {
	uint64_t opt_value;
	uint32_t name_size;
	uint32_t volume_name_size;
	uint8_t flag;
} __attribute__((packed));

struct par_net_open_rep {
	uint64_t region_id;
	uint32_t status;
} __attribute__((packed));

uint32_t par_net_get_size(const char *buffer)
{
	return strlen(buffer) + 1;
}

size_t par_net_open_req_calc_size(uint32_t name_size, uint32_t volume_name_size)
{
	return sizeof(struct par_net_open_req) + name_size + volume_name_size;
}

size_t par_net_open_rep_calc_size()
{
	return sizeof(struct par_net_open_rep);
}

struct par_net_open_req *par_net_open_req_create(uint8_t flag, uint32_t name_size, const char *name,
						 uint32_t volume_name_size, const char *volume_name, uint64_t opt_value,
						 char *buffer, size_t *buffer_len)
{
	if (par_net_open_req_calc_size(name_size, volume_name_size) > *buffer_len)
		return NULL;

	struct par_net_open_req *request = (struct par_net_open_req *)(buffer + sizeof(uint32_t));
	request->flag = flag;
	request->name_size = name_size;
	request->volume_name_size = volume_name_size;
	request->opt_value = opt_value;

	memcpy(&buffer[sizeof(uint32_t) + sizeof(struct par_net_open_req)], name, name_size);
	memcpy(&buffer[sizeof(uint32_t) + sizeof(struct par_net_open_req) + name_size], volume_name, volume_name_size);

	return request;
}

uint64_t par_net_open_get_optvalue(struct par_net_open_req *request)
{
	return request->opt_value;
}

uint8_t par_net_open_get_flag(struct par_net_open_req *request)
{
	return request->flag;
}

char *par_net_open_get_dbname(struct par_net_open_req *request)
{
	return (char *)request + sizeof(struct par_net_open_req);
}

char *par_net_open_get_volname(struct par_net_open_req *request)
{
	return (char *)request + sizeof(struct par_net_open_req) + request->name_size;
}

struct par_net_open_rep *par_net_open_rep_create(int status, par_handle handle, size_t *rep_len)
{
	struct par_net_open_rep *reply = malloc(sizeof(struct par_net_open_rep));
	*rep_len = par_net_open_rep_calc_size();

	reply->status = status;

	if (status == 1)
		return reply;

	uint64_t handle_value = (uint64_t)(uintptr_t)handle;
	reply->region_id = handle_value;

	return reply;
}

par_handle par_net_open_rep_handle_reply(char *buffer)
{
	struct par_net_open_rep *reply = (struct par_net_open_rep *)buffer;
	if (reply->status == 1) {
		log_fatal("Server reply fail");
		_exit(EXIT_FAILURE);
	}

	uint64_t handle_value = reply->region_id;
	par_handle handle = (par_handle)(uintptr_t)handle_value;

	return handle;
}
