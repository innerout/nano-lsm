#ifndef PAR_NET_DELETE_H
#define PAR_NET_DELETE_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REP_FAIL 1
#define REP_SUCCESS 0

struct par_net_del_req;

struct par_net_rep;

/**
  * @brief calculates total size of par_net_del_req struct and the sizes
  * of the key and value.
  *
  *	@param key_size
  *
  * @return Total size of struct and key
  *
  */
size_t par_net_del_calc_size(uint32_t key_size);

/**
  *
  * @brief Constructor for the par_net_del class, initializes values to be
  * ready for serialization
  *
  * @param region_id
  * @param key_size
  * @param key
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  *
  */
struct par_net_del_req *par_net_del_req_create(uint64_t region_id, uint32_t key_size, const char *key, char *buffer,
					       size_t *buffer_len);
/**
  *
  * @brief Serializes par_delete data to be sent over through the network
  *
  * @param request
  * @param buffer_len
  *
  * @return buffer of serialized data on success and NULL on failure
  *
  */
char *par_net_del_serialize(struct par_net_del_req *request, size_t *buffer_len);

/**
  *
  * @brief Deserializes par_delete data after sent through the network
  *
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the par_net_put_req struct on success and NULL on failure
  *
  */
struct par_net_rep par_net_call_del(char *buffer);

uint64_t par_net_del_get_region_id(struct par_net_del_req *request);

uint32_t par_net_del_get_key_size(struct par_net_del_req *request);

char *par_net_del_get_key(struct par_net_del_req *request);

#endif
