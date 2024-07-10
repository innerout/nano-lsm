#include "par_net.h"

deserializer par_net_deserialize[] = { par_net_error, par_net_open_deserialize, par_net_put_deserialize,
				       par_net_del_deserialize };

struct par_net_rep par_net_error(char *buffer, size_t *buffer_len)
{
	struct par_net_rep error_rep;
	error_rep.status = REP_FAIL;
	return error_rep;
}

uint32_t par_find_opcode(char *buffer)
{
	uint32_t opcode;
	memcpy(&opcode, buffer, sizeof(uint32_t));

	if (opcode >= MAX_OPCODE)
		return 0;

	return opcode;
}
