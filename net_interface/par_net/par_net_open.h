#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct __attribute__((packed)) par_net_open_req {
	uint8_t flag;
	uint32_t name_size;
	uint32_t volume_name_size;
	uint64_t opt_value;
};

struct __attribute__((packed)) par_net_open_rep {
	uint32_t status;
};

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
  * @brief Serializes par_open data to be sent over through the network
  *
  * @param request
  * @param buffer_len
  *
  * @return buffer of serialized data on success and NULL on failure
  *
  */
char *par_net_open_serialize(struct par_net_open_req *request, size_t *buffer_len);

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
struct par_net_open_rep *par_net_open_deserialize(char *buffer, size_t *buffer_len);
