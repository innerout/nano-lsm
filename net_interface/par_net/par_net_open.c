#include "par_net_open.h"

size_t par_net_open_calc_size(uint32_t name_size, uint32_t volume_name_size)
{
	return sizeof(struct par_net_open_req) + name_size + volume_name_size;
}

struct par_net_open_req *par_net_open_req_create(uint8_t flag, uint32_t name_size, const char *name,
						 uint32_t volume_name_size, const char *volume_name, uint64_t opt_value,
						 char *buffer, size_t *buffer_len)
{
	if (par_net_open_calc_size(name_size, volume_name_size) > *buffer_len)
		return NULL;

	struct par_net_open_req *request = (struct par_net_open_req *)buffer;
	request->flag = flag;
	request->name_size = name_size;
	request->volume_name_size = volume_name_size;
	request->opt_value = opt_value;

	memcpy(buffer + sizeof(struct par_net_open_req), name, name_size);
	memcpy(buffer + sizeof(struct par_net_open_req) + name_size, volume_name, volume_name_size);

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

	memcpy(buffer, request, sizeof(struct par_net_open_req));

	memcpy(buffer + sizeof(struct par_net_open_req), (char *)request + sizeof(struct par_net_open_req),
	       request->name_size);

	memcpy(buffer + sizeof(struct par_net_open_req) + request->name_size,
	       (char *)request + sizeof(struct par_net_open_req) + request->name_size, request->volume_name_size);

	return buffer;
}

struct par_net_open_rep *par_net_open_deserialize(char *buffer, size_t *buffer_len)
{
	if (*buffer_len < sizeof(struct par_net_open_req))
		return NULL;

	struct par_net_open_req *request = (struct par_net_open_req *)malloc(sizeof(struct par_net_open_req));
	if (!request) {
		return NULL;
	}

	memcpy(request, buffer, sizeof(struct par_net_open_req));

	size_t actual_size = par_net_open_calc_size(request->name_size, request->volume_name_size);
	if (*buffer_len < actual_size) {
		//call destroy here
		return NULL;
	}

	char *name = malloc(request->name_size);
	char *volume_name = malloc(request->volume_name_size);
	if (!name || !volume_name) {
		//call destroy here
		return NULL;
	}

	memcpy(name, buffer + sizeof(struct par_net_open_req), request->name_size);
	memcpy(volume_name, buffer + sizeof(struct par_net_open_req) + request->name_size, request->volume_name_size);

	//Call par_open from parallax public api

	struct par_net_open_rep *open_rep;
	open_rep->status = 0;

	return open_rep;
}
