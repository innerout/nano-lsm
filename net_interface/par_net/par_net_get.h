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

/**
 * @brief getter for region_id
 *
 * @param request
 *
 * @return region_id
*/
uint64_t par_net_get_get_region_id(struct par_net_get_req *request);

/**
 * @brief getter for key size
 *
 * @param request
 *
 * @return key size
*/
uint32_t par_net_get_get_key_size(struct par_net_get_req *request);

/**
 * @brief getter for value size
 *
 * @param request
 *
 * @return value size
*/
uint32_t par_net_get_get_value_size(struct par_net_get_req *request);

/**
 * @brief getter for key
 *
 * @param request
 *
 * @return key
*/
char *par_net_get_get_key(struct par_net_get_req *request);

/**
 * @brief getter for value
 *
 * @param request
 *
 * @return value
*/
char *par_net_get_get_value(struct par_net_get_req *request);

/**
 * @brief calculates the size of the par_net_del_req struct
 *
 * @return the par_net_del_rep struct's size
*/
size_t par_net_get_rep_calc_size(void);

/**
 * @brief Constructor for the par_net_get_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param rep_len - length of the reply
 *
 * @return par_net_get_rep object
*/
struct par_net_get_rep *par_net_get_rep_create(int status, size_t *rep_len);

/**
 * @brief Takes the reply from server and checks if it's done correctly
 *
 * @param buffer
 *
*/
void par_net_get_rep_handle_reply(char *buffer);

#endif