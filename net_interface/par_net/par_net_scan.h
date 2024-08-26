#ifndef PAR_NET_SCAN_H
#define PAR_NET_SCAN_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <stdint.h>
#include <unistd.h>

struct par_net_scan_req;

struct par_net_scan_rep;

size_t par_net_scan_req_calc_size(uint32_t key_size);
uint64_t par_net_scan_req_get_region_id(struct par_net_scan_req *request);
par_seek_mode par_net_scan_req_get_seek_mode(struct par_net_scan_req *request);
uint32_t par_net_scan_req_get_key_size(struct par_net_scan_req *request);
const char *par_net_scan_req_get_key(struct par_net_scan_req *request);
uint32_t par_net_scan_req_get_max_entries(struct par_net_scan_req *request);

struct par_net_scan_req *par_net_scan_req_create(uint64_t region_id, struct par_key *key, uint32_t max_kv_pairs,
						 par_seek_mode mode, char *buffer, size_t buffer_len);

//--- reply staff follows

size_t par_net_scan_rep_header_calc_size(void);

bool par_net_scan_rep_has_more(struct par_net_scan_rep *reply);

void par_net_scan_rep_set_valid(struct par_net_scan_rep *reply, bool valid);

bool par_net_scan_rep_is_valid(struct par_net_scan_rep *reply);

struct par_net_scan_rep *par_net_scan_rep_create(uint32_t max_kv_pairs, char *buffer, size_t buffer_len);

uint32_t par_net_scan_rep_get_size(struct par_net_scan_rep *reply);

bool par_net_scan_rep_append_splice(struct par_net_scan_rep *reply, int32_t key_size, const char *key,
				    int32_t value_size, const char *value);

uint32_t par_net_scan_rep_get_num_entries(struct par_net_scan_rep *reply);

bool par_net_scan_rep_seek2_to_first(struct par_net_scan_rep *reply);

bool par_net_scan_rep_seek2_next_splice(struct par_net_scan_rep *reply);

struct kv_splice *par_net_scan_rep_get_last_splice(struct par_net_scan_rep *reply);

struct kv_splice *par_net_scan_rep(struct par_net_scan_rep *reply);
#endif
