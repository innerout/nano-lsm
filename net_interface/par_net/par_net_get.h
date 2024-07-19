#ifndef PAR_NET_GET_H
#define PAR_NET_GET_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_get_req;

struct par_net_get_rep;

size_t par_net_get_req_calc_size(uint32_t key_size, uint32_t value_size);

struct par_net_get_req *par_net_get_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer,
					       size_t *buffer_len);

char *par_net_call_get(char *buffer, size_t *buffer_len);

uint64_t par_net_get_get_region_id(struct par_net_get_req *request);

uint32_t par_net_get_get_key_size(struct par_net_get_req *request);

uint32_t par_net_get_get_value_size(struct par_net_get_req *request);

char *par_net_get_get_key(struct par_net_get_req *request);

char *par_net_get_get_value(struct par_net_get_req *request);

size_t par_net_get_rep_calc_size();

struct par_net_get_rep *par_net_get_rep_create(int status, size_t *rep_len);

void par_net_get_rep_handle_reply(char *buffer);

#endif
