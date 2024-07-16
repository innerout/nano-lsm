#ifndef PAR_NET_H
#define PAR_NET_H

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

#include "par_net_delete.h"
#include "par_net_open.h"
#include "par_net_put.h"

#define MAX_OPCODE 4

#if __BIG_ENDIAN__
#define htonl_64(x) (x)
#define ntohl_64(x) (x)
#else
#define htonl_64(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohl_64(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

enum par_net_op { OPCODE_OPEN = 1, OPCODE_PUT, OPCODE_DEL };

typedef struct par_net_rep (*par_call)(char *buffer);
typedef uint32_t (*par_get_32)(char *buffer);
typedef uint64_t (*par_get_64)(char *buffer);

extern par_call par_net_call[4];
extern par_get_32 par_get_key_size[4];
extern par_get_32 par_get_value_size[4];
extern par_get_64 par_get_regionid[4];

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
  *  @brief This function is called whenever there is an invalid opcode
  *
  *  @param buffer
  *  @param buffer_len
  *
  *  @return a failed server reply
  */
struct par_net_rep par_net_error(char *buffer);

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
struct par_net_rep par_net_call_put(char *buffer);

/**
  *  @brief Sends buffer to the server
  *
  *  @param buffer
  *  @param buffer_len
  *
  *  @return 0 on success and 1 on failure
  */
static int par_net_send(char *buffer, size_t *buffer_len);

#endif
