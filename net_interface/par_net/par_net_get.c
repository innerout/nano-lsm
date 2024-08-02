#include "par_net_get.h"
#include "log.h"
#include "par_net.h"
#include <stdint.h>

struct par_net_get_req {
	uint64_t region_id;
	uint32_t key_size;
} __attribute__((packed));

struct par_net_get_rep {
	uint32_t is_found;
  uint32_t value_size;
  uint32_t total_bytes;
} __attribute__((packed));

size_t par_net_get_req_calc_size(uint32_t key_size)
{
	return sizeof(struct par_net_get_req) + key_size;
}

size_t par_net_get_rep_calc_size(uint32_t value_size)
{
	return sizeof(struct par_net_get_rep) + value_size;
}

struct par_net_get_req *par_net_get_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					        char *buffer, size_t *buffer_len)
{
	if (par_net_get_req_calc_size(key_size) > *buffer_len)
		return NULL;

	struct par_net_get_req *request = (struct par_net_get_req *)(buffer);
	request->region_id = region_id;
	request->key_size = key_size;

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

struct par_net_get_rep *par_net_get_rep_create(int is_found,struct par_value *v,size_t *rep_len)
{

  *rep_len = par_net_get_rep_calc_size(v->val_size);
  struct par_net_get_rep *reply = malloc(*rep_len);

  reply->total_bytes = *rep_len;
	reply->is_found = is_found;
  if(!is_found)
    return reply;

  char* reply_buffer = (char*)reply;
  log_debug("Val size (creating rep object) == %lu", (unsigned long)v->val_size);
  reply->value_size = v->val_size;
  memcpy(&reply_buffer[sizeof(struct par_net_get_rep)], v->val_buffer, v->val_size);

	return reply;
}

int par_net_get_rep_handle_reply(char *buffer ,struct par_value *v)
{
	struct par_net_get_rep *reply = (struct par_net_get_rep *)buffer;

	if (!reply->is_found) {	
    return 1;
	}

  v->val_size = reply->value_size;
  v->val_buffer_size = reply->value_size;
 
  log_debug("val size == %lu", (unsigned long)reply->value_size);
  v->val_buffer = calloc(1UL, v->val_size);

  memcpy(v->val_buffer, &buffer[sizeof(struct par_net_get_rep)], v->val_size);
	return 0;
}
