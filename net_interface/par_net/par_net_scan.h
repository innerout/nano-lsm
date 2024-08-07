#ifndef PAR_NET_SCAN_H
#define PAR_NET_SCAN_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <stdint.h>
#include <unistd.h>

struct par_net_scan_req;

struct par_net_scan_rep;

size_t par_net_scan_req_calc_size(uint32_t key_size);

size_t par_net_scan_rep_calc_size(uint32_t value_size);

struct par_net_scan_req *par_net_scan_req_create(uint64_t region_id, uint32_t key_size, const char *key,
						 uint32_t max_entries, par_seek_mode mode, char *buffer,
						 size_t *buffer_len);

//--- reply staff follow

#endif
