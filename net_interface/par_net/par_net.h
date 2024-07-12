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

#define MAX_OPCODE 4

#if __BIG_ENDIAN__
#define htonl_64(x) (x)
#define ntohl_64(x) (x)
#else
#define htonl_64(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohl_64(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

enum par_net_op { OPCODE_OPEN = 1, OPCODE_PUT, OPCODE_DEL };

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
static int par_net_send(char *buffer, size_t *buffer_len);

#endif
