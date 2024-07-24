#ifndef PAR_NET_OPEN_H
#define PAR_NET_OPEN_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_open_req;

struct par_net_open_rep;

/**
  * @brief calcutes the size of a string
  *
  * @param buffer
  *
  * @return the string's size
  */
uint32_t par_net_get_size(const char *buffer);

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
size_t par_net_open_req_calc_size(uint32_t name_size, uint32_t volume_name_size);

/**
  *
  * @brief Constructor for the par_net_open_req class, initializes values to be
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
 * @brief Calls par_open from the server side using the parallax public API
 *
 * @param buffer
 * @param buffer_len
 *
 * @return A buffer containing the server's reply
 *
*/
char *par_net_call_open(char *buffer, size_t *buffer_len);

/**
 * @brief getter for options->value
 *
 * @param request
 *
 * @return options->value
*/
uint64_t par_net_open_get_optvalue(struct par_net_open_req *request);

/**
 * @brief getter for database name size
 *
 * @param request
 *
 * @return length of database name
*/
uint32_t par_net_open_get_db_name_size(struct par_net_open_req *request);

/**
 * @brief getter for volume string size
 *
 * @param request
 *
 * @return length of volume name
*/
uint32_t par_net_open_get_volume_size(struct par_net_open_req *request);

/**
 * @brief getter for db flag
 *
 * @param request
 *
 * @return db flag
*/
uint8_t par_net_open_get_flag(struct par_net_open_req *request);

/**
 * @brief getter for database name
 *
 * @param request
 *
 * @return database name
*/
char *par_net_open_get_dbname(struct par_net_open_req *request);

/**
 * @brief getter for volume name
 *
 * @param request
 *
 * @return volume name
*/
char *par_net_open_get_volname(struct par_net_open_req *request);

/**
 * @brief calculates the size of the par_net_open_req struct
 *
 * @return the par_net_open_rep struct's size
*/
size_t par_net_open_rep_calc_size(void);

/**
 * @brief Constructor for the par_net_open_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param handle - par_open return value
 * @param rep_len - length of the reply
 *
 * @return par_net_open_rep object
*/
struct par_net_open_rep *par_net_open_rep_create(int status, par_handle handle, size_t *rep_len);

/**
 * @brief Takes the reply from server and gets the return value for par_open for the client
 *
 * @param buffer
 *
 * @return par_open return value
 *
*/
par_handle par_net_open_rep_handle_reply(char *buffer);

#endif
