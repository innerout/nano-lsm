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

#define REP_FAIL 1
#define REP_SUCCESS 0

#define MAX_OPCODE 4

#if __BIG_ENDIAN__
#define htonl_64(x) (x)
#define ntohl_64(x) (x)
#else
#define htonl_64(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohl_64(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

enum par_net_op { OPCODE_OPEN = 1, OPCODE_PUT, OPCODE_DEL };

struct par_net_put_req {
	uint64_t region_id;
	uint32_t key_size;
	uint32_t value_size;
} __attribute__((packed));

struct par_net_open_req {
	uint64_t opt_value;
	uint32_t name_size;
	uint32_t volume_name_size;
	uint8_t flag;
} __attribute__((packed));

struct par_net_del_req {
	uint64_t region_id;
	uint32_t key_size;
} __attribute__((packed));

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

typedef struct par_net_rep (*deserializer)(char *buffer, size_t *buffer_len);

extern deserializer par_net_deserialize[4];

/**
 *  @brief Takes the first byte of the serialized stream and translates it to
 *  an opcode to see which of the deserialization function should be called
 *
 *  @param buffer
 *
 *  @return the uint8_t opcode
 *
 */
uint32_t par_find_opcode(char *buffer);

/**
  * @brief calculates total size of par_net_put_req struct and the sizes
  * of the key and value.
  *
  *	@param key_size
  *	@param value_size
  *
  * @return Total size of struct, key and value
  *
  */
size_t par_net_put_calc_size(uint32_t key_size, uint32_t value_size);

/**
  *
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

/**
 * @brief calcutes the size of a string
 *
 * @param buffer
 *
 * @return the string's size
*/
size_t get_size(const char *buffer);

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
struct par_net_rep par_net_open_deserialize(char *buffer, size_t *buffer_len);

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
struct par_net_rep par_net_del_deserialize(char *buffer, size_t *buffer_len);

/**
 *  @brief This function is called whenever there is an invalid opcode
 *
 *  @param buffer
 *  @param buffer_len
 *
 *  @return a failed server reply
 */
struct par_net_rep par_net_error(char *buffer, size_t *buffer_len);

/**
 *  @brief Sends buffer to the server
 *
 *  @param buffer
 *  @param buffer_len
 *
 *  @return 0 on success and 1 on failure
 */
int par_net_send(char *buffer, size_t *buffer_len);
