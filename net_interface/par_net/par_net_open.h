#ifndef PAR_NET_OPEN_H
#define PAR_NET_OPEN_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REP_FAIL 1
#define REP_SUCCESS 0

struct par_net_open_req;

struct par_net_rep;

/**
  * @brief calcutes the size of a string
  *
  * @param buffer
  *
  * @return the string's size
  */
uint32_t get_size(const char *buffer);

/**
  * @brief calculates total size of par_net_open_req struct and the sizes
  * of the key and value.
  *
  *	@param name_size
  *	@param volume_name_size
  *
  * @return Total size of struct, name and volume name
  *
  */
size_t par_net_open_calc_size(uint32_t name_size, uint32_t volume_name_size);

/**
  *
  * @brief Constructor for the par_net_open class, initializes values to be
  * ready for serialization
  *
  * @param flag
  * @param name_size
  * @param name
  * @param volume_name_size
  * @param volume_name
  * @param opt_value
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  *
  */
struct par_net_open_req *par_net_open_req_create(uint8_t flag, uint32_t name_size, const char *name,
						 uint32_t volume_name_size, const char *volume_name, uint64_t opt_value,
						 char *buffer, size_t *buffer_len);

/**
  *
  * @brief Deserializes par_open data after sent through the network
  *
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the par_net_put_req struct on success and NULL on failure
  *
  */
struct par_net_rep par_net_call_open(char *buffer);

uint64_t par_net_open_get_optvalue(struct par_net_open_req *request);

uint32_t par_net_open_get_db_name_size(struct par_net_open_req *request);

uint32_t par_net_open_get_volume_size(struct par_net_open_req *request);

uint8_t par_net_open_get_flag(struct par_net_open_req *request);

char *par_net_open_get_dbname(struct par_net_open_req *request);

char *par_net_open_get_volname(struct par_net_open_req *request);

#endif
