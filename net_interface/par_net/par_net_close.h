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

/**
  * @brief calculates total size of par_net_close_req struct and the sizes
  * of the key and value.
  *
  * @return Total size of struct
  */
uint32_t par_net_close_req_calc_size(void);

/**
  *
  * @brief Constructor for the par_net_close class, initializes values to be
  * ready for serialization
  *
  * @param region_id
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  */
struct par_net_close_req *par_net_close_req_create(uint64_t region_id, char *buffer, size_t *buffer_len);

/**
 * @brief getter for region_id
 *
 * @param request
 *
 * @return region_id
*/
uint64_t par_net_close_get_region_id(struct par_net_close_req *request);

/**
 * @brief calculates the size of the par_net_close_req struct
 *
 * @return the par_net_del_rep struct's size
*/
size_t par_net_close_rep_calc_size(uint32_t string_size);

/**
 * @brief Constructor for the par_net_close_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param return_string - return value of par_close
 * @param rep_len - length of the reply
 *
 * @return par_net_close_rep object
*/
struct par_net_close_rep *par_net_close_rep_create(const char *error_message, char *buffer, size_t buffer_len);

/**
  * @brief getter for the par_close error_messsge string
  *
  * @param reply
  *
  * @return error_messsge
  */
const char *par_net_close_get_string(struct par_net_close_rep *reply);

/**
 * @brief Takes the reply from server and checks if it's done correctly
 *
 * @param buffer
 *
*/
const char *par_net_close_rep_handle_reply(struct par_net_close_rep *reply);

#endif
