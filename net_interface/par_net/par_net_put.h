#ifndef PAR_NET_PUT_H
#define PAR_NET_PUT_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_put_req;

struct par_net_put_rep;

size_t par_net_put_req_calc_size(uint32_t key_size, uint32_t value_size);

/**
  * @brief Constructor for the par_net_put class, initializes values to be
  * ready for serialization
  *
  * @param region_id
  * @param key_size
  * @param key
  * @param value_size
  * @param value
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  *
  */
struct par_net_put_req *par_net_put_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer,
					       size_t *buffer_len);

struct par_net_put_req *par_net_put_destroy(struct par_net_put_req *request);

char *par_net_call_put(char *buffer, size_t *buffer_len);

uint64_t par_net_put_get_region_id(struct par_net_put_req *request);

uint32_t par_net_put_get_key_size(struct par_net_put_req *request);

uint32_t par_net_put_get_value_size(struct par_net_put_req *request);

char *par_net_put_get_key(struct par_net_put_req *request);

char *par_net_put_get_value(struct par_net_put_req *request);

size_t par_net_put_rep_calc_size();

struct par_net_put_rep *par_net_put_rep_create(int status, struct par_put_metadata metadata, size_t *rep_len);

struct par_put_metadata par_net_put_rep_handle_reply(char *buffer);

#endif
