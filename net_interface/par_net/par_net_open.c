#include "par_net_open.h"

struct par_net_open_req {
	uint64_t opt_value;
	uint32_t name_size;
	uint32_t volume_name_size;
	uint8_t flag;
} __attribute__((packed));

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

uint32_t get_size(const char *buffer)
{
	return strlen(buffer) + 1;
}

size_t par_net_open_calc_size(uint32_t name_size, uint32_t volume_name_size)
{
	return sizeof(uint32_t) + sizeof(struct par_net_open_req) + name_size + volume_name_size;
}

struct par_net_open_req *par_net_open_req_create(uint8_t flag, uint32_t name_size, const char *name,
						 uint32_t volume_name_size, const char *volume_name, uint64_t opt_value,
						 char *buffer, size_t *buffer_len)
{
	if (par_net_open_calc_size(name_size, volume_name_size) > *buffer_len)
		return NULL;

	struct par_net_open_req *request = (struct par_net_open_req *)(buffer + sizeof(uint32_t));
	request->flag = flag;
	request->name_size = name_size;
	request->volume_name_size = volume_name_size;
	request->opt_value = opt_value;

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req), name, name_size);
	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req) + name_size, volume_name, volume_name_size);

	return request;
}

char *par_net_open_serialize(struct par_net_open_req *request, size_t *buffer_len)
{
	char *buffer = (char *)request - sizeof(uint32_t);
	return buffer;
}

struct par_net_rep par_net_open_deserialize(char *buffer, size_t *buffer_len)
{
	struct par_net_rep open_reply;
	if (*buffer_len < sizeof(struct par_net_open_req)) {
		open_reply.status = REP_FAIL;
		return open_reply;
	}

	struct par_net_open_req *request = (struct par_net_open_req *)(buffer + sizeof(uint32_t));

	char *db_name = (char *)malloc(request->name_size);
	char *volume_name = (char *)malloc(request->volume_name_size);

	memcpy(db_name, buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req), request->name_size);
	memcpy(volume_name, buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req) + request->name_size,
	       request->volume_name_size);

	par_db_options *db_options = malloc(sizeof(par_db_options));
	db_options->options = malloc(sizeof(struct par_options_desc));

	db_options->create_flag = request->flag;
	db_options->db_name = db_name;
	db_options->options->value = request->opt_value;
	db_options->volume_name = volume_name;

	par_open(db_options, NULL);

	//Call destroy here

	open_reply.status = REP_SUCCESS;
	return open_reply;
}
