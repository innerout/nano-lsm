#ifndef PAR_NET_H
#define PAR_NET_H

#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "par_net_close.h"
#include "par_net_delete.h"
#include "par_net_get.h"
#include "par_net_open.h"
#include "par_net_put.h"
struct worker;

enum par_net_op { OPCODE_OPEN = 1, OPCODE_PUT, OPCODE_DEL, OPCODE_GET, OPCODE_CLOSE };

typedef char *(*par_call)(struct worker *worker, char *buffer, size_t *buffer_len, void *args);

/**
  *  @brief Takes the first byte of the serialized stream and translates it to
  *  an opcode to see which of the deserialization function should be called
  *
  *  @param buffer
  *
  *  @return the uint8_t opcode
  *
  */
uint32_t par_net_header_get_opcode(char *buffer);

/**
  *  @brief Sends buffer to the server
  *
  *  @param buffer
  *  @param buffer_len
  *
  *  @return reply buffer on success and NULL on failure
  */
char *par_net_send(char *buffer, size_t *buffer_len);

#endif
