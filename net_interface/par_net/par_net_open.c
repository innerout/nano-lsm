#include "par_net.h"

size_t get_size(const char *buffer)
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

	uint32_t opcode = OPCODE_OPEN;
	buffer[0] = opcode;

	struct par_net_open_req *request = (struct par_net_open_req *)buffer;
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
	*buffer_len = par_net_open_calc_size(request->name_size, request->volume_name_size);

	char *buffer = malloc(*buffer_len);
	if (!buffer) {
		*buffer_len = 0;
		return NULL;
	}

	uint32_t opcode = OPCODE_OPEN;
	buffer[0] = opcode;
	memcpy(buffer + sizeof(uint32_t), request, sizeof(struct par_net_open_req));

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req),
	       (char *)request + sizeof(struct par_net_open_req), request->name_size);

	memcpy(buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req) + request->name_size,
	       (char *)request + sizeof(struct par_net_open_req) + request->name_size, request->volume_name_size);

	return buffer;
}

struct par_net_rep par_net_open_deserialize(char *buffer, size_t *buffer_len)
{
	struct par_net_rep open_rep;
	if (*buffer_len < sizeof(uint32_t) + sizeof(struct par_net_open_req)) {
		open_rep.status = REP_FAIL;
		return open_rep;
	}

	buffer += sizeof(uint32_t);

	struct par_net_open_req *request = (struct par_net_open_req *)malloc(sizeof(struct par_net_open_req));
	if (!request) {
		open_rep.status = REP_FAIL;
		return open_rep;
	}

	memcpy(request, buffer, sizeof(struct par_net_open_req));

	size_t actual_size = par_net_open_calc_size(request->name_size, request->volume_name_size);
	if (*buffer_len < actual_size) {
		//call destroy here
		open_rep.status = REP_FAIL;
		return open_rep;
	}

	char *name = malloc(request->name_size);
	char *volume_name = malloc(request->volume_name_size);
	if (!name || !volume_name) {
		//call destroy here
		open_rep.status = REP_FAIL;
		return open_rep;
	}

	memcpy(name, buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req), request->name_size);
	memcpy(volume_name, buffer + sizeof(uint32_t) + sizeof(struct par_net_open_req) + request->name_size,
	       request->volume_name_size);

	par_db_options *db_options = malloc(sizeof(par_db_options));

	db_options->create_flag = request->flag;
	db_options->db_name = name;
	db_options->options->value = request->opt_value;
	db_options->volume_name = volume_name;

	if (!par_open(db_options, NULL)) {
		//Call destroy here
		open_rep.status = REP_FAIL;
	}

	open_rep.status = REP_SUCCESS;

	//Call destroy here
	return open_rep;
}
