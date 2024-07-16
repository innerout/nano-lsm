#include "par_net.h"

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

par_call par_net_call[] = { par_net_error, par_net_call_open, par_net_call_put, par_net_call_del };

struct par_net_rep par_net_error(char *buffer)
{
	perror("OPCODE_ERROR");
	struct par_net_rep err_rep;
	err_rep.status = 1;
	return err_rep;
}

uint32_t par_find_opcode(char *buffer)
{
	uint32_t opcode;
	memcpy(&opcode, buffer, sizeof(uint32_t));

	if (opcode >= MAX_OPCODE)
		return 0;

	return opcode;
}
