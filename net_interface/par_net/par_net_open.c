#include "par_net_open.h"
#include "log.h"
#include "par_net.h"

struct par_net_open_req {
	uint64_t opt_value;
	uint32_t db_name_size;
	uint8_t flag;
} __attribute__((packed));

struct par_net_open_rep {
	uint64_t region_id;
	uint32_t status;
  uint32_t total_bytes;
} __attribute__((packed));

uint32_t par_net_get_size(const char *buffer)
{
	return strlen(buffer) + 1;
}

size_t par_net_open_req_calc_size(uint32_t name_size)
{
	return sizeof(struct par_net_open_req) + name_size;
}

size_t par_net_open_rep_calc_size(void)
{
	return sizeof(struct par_net_open_rep);
}

struct par_net_open_req *par_net_open_req_create(uint8_t flag, const char *name,
						 char *buffer, size_t *buffer_len)
{
	uint32_t db_name_size = par_net_get_size(name);
	if (par_net_open_req_calc_size(db_name_size) > *buffer_len)
		return NULL;

	struct par_net_open_req *request = (struct par_net_open_req *)(buffer);
	request->flag = flag;
	request->db_name_size = db_name_size;

	memcpy(&buffer[sizeof(struct par_net_open_req)], name, db_name_size);

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

struct par_net_open_rep *par_net_open_rep_create(int status, par_handle handle, size_t *rep_len)
{
	struct par_net_open_rep *reply = malloc(sizeof(struct par_net_open_rep));
	*rep_len = par_net_open_rep_calc_size();

  log_debug("Rep len == %lu", *rep_len);
	reply->status = status;

	if (status == 1)
		return reply;

	reply->region_id = (uint64_t)handle;

	return reply;
}

par_handle par_net_open_rep_handle_reply(char *buffer)
{
	struct par_net_open_rep *reply = (struct par_net_open_rep *)buffer;
	if (reply->status == 1) {
		log_fatal("Invalid Reply status");
		_exit(EXIT_FAILURE);
	}
  
	par_handle handle = (par_handle)reply->region_id;


	return handle;
}
