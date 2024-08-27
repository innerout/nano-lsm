#include <log.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct par_net_sync_req {
	uint64_t region_id;
} __attribute((packed));

struct par_net_sync_rep {
	uint64_t region_id;
	int status;
} __attribute((packed));

size_t par_net_sync_req_calc_size(void)
{
	return sizeof(struct par_net_sync_req);
}

uint64_t par_net_sync_req_get_region_id(struct par_net_sync_req *request)
{
	return request->region_id;
}

struct par_net_sync_req *par_net_sync_req_create(uint64_t region_id, char *buffer, uint32_t buffer_len)
{
	if (buffer_len < par_net_sync_req_calc_size()) {
		log_warn("Buffer too small needs %lu B got %u B", par_net_sync_req_calc_size(), buffer_len);
		return NULL;
	}
	struct par_net_sync_req *request = (struct par_net_sync_req *)buffer;
	request->region_id = region_id;
	return request;
}

//--reply part

size_t par_net_sync_rep_calc_size(void)
{
	return sizeof(struct par_net_sync_rep);
}

struct par_net_sync_rep *par_net_sync_rep_create(int status, uint64_t region_id, char *buffer, size_t buffer_len)
{
	if (buffer_len < par_net_sync_req_calc_size())
		return NULL;
	struct par_net_sync_rep *reply = (struct par_net_sync_rep *)buffer;
	reply->region_id = region_id;
	reply->status = status;
	return reply;
}

int par_net_sync_rep_get_status(struct par_net_sync_rep *reply)
{
	return reply->status;
}
