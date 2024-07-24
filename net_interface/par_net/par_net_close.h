#ifndef PAR_NET_CLOSE_H
#define PAR_NET_CLOSE_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_close_req;

struct par_net_close_rep;

uint32_t par_net_close_req_calc_size(void);

size_t par_net_close_rep_calc_size(uint32_t string_size);

struct par_net_close_req *par_net_close_req_create(uint64_t region_id, char *buffer, size_t *buffer_len);

uint64_t par_net_close_get_region_id(struct par_net_close_req *request);

char* par_net_call_close(char *buffer, size_t *buffer_len);

struct par_net_close_rep *par_net_close_rep_create(int status, const char* return_string, size_t *rep_len);

const char* par_net_close_get_string(struct par_net_close_rep *reply);

const char* par_net_close_rep_handle_reply(char* buffer);

#endif