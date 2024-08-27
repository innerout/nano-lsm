#ifndef PAR_NET_SYNC_H
#define PAR_NET_SYNC_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct par_net_sync_req;

struct par_net_sync_rep;

size_t par_net_sync_req_calc_size(void);

struct par_net_sync_req *par_net_sync_req_create(uint64_t region_id, char *buffer, uint32_t buffer_len);

uint64_t par_net_sync_req_get_region_id(struct par_net_sync_req *request);

//--reply part

size_t par_net_sync_rep_calc_size(void);

struct par_net_sync_rep *par_net_sync_rep_create(int status, uint64_t region_id, char *buffer, size_t buffer_len);

int par_net_sync_rep_get_status(struct par_net_sync_rep *reply);

#endif
