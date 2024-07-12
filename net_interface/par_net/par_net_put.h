#ifndef PAR_NET_PUT_H
#define PAR_NET_PUT_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REP_FAIL 1
#define REP_SUCCESS 0

struct par_net_put_req;

struct par_net_rep;

size_t par_net_put_calc_size(uint32_t key_size, uint32_t value_size);
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

/**
  *
  * @brief Serializes par_put data to be sent over through the network
  *
  * @param request
  * @param buffer_len
  *
  * @return buffer of serialized data on success and NULL on failure
  *
  */
char *par_net_put_serialize(struct par_net_put_req *request, size_t *buffer_len);

/**
  *
  * @brief Deserializes par_put data after sent through the network
  *
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the par_net_put_req struct on success and NULL on failure
  *
  */
struct par_net_rep par_net_put_deserialize(char *buffer, size_t *buffer_len);

struct par_net_put_req *par_net_put_destroy(struct par_net_put_req *par_put_request);

#endif
