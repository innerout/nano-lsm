#ifndef PAR_NET_DELETE_H
#define PAR_NET_DELETE_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_del_req;

struct par_net_del_rep;

/**
  * @brief calculates total size of par_net_del_req struct and the sizes
  * of the key and value.
  *
  *	@param key_size
  *
  * @return Total size of struct and key
  *
  */
size_t par_net_del_req_calc_size(uint32_t key_size);

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

char *par_net_call_del(char *buffer, size_t *buffer_len);

/**
 * @brief getter for region_id
 *
 * @param request
 *
 * @return region_id
*/
uint64_t par_net_del_get_region_id(struct par_net_del_req *request);

/**
 * @brief getter for key size
 *
 * @param request
 *
 * @return key size
*/
uint32_t par_net_del_get_key_size(struct par_net_del_req *request);

/**
 * @brief getter for key
 *
 * @param request
 *
 * @return key
*/
char *par_net_del_get_key(struct par_net_del_req *request);

/**
 * @brief calculates the size of the par_net_del_req struct
 *
 * @return the par_net_del_rep struct's size
*/
size_t par_net_del_rep_calc_size();

/**
 * @brief Constructor for the par_net_del_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param rep_len - length of the reply
 *
 * @return par_net_del_rep object
*/
struct par_net_del_rep *par_net_del_rep_create(int status, size_t *rep_len);

/**
 * @brief Takes the reply from server and checks if it's done correctly
 *
 * @param buffer
 *
*/
void par_net_del_rep_handle_reply(char *buffer);

#endif
