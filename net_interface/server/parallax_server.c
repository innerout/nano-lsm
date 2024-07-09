#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"
#include <stdio.h>

#include "server_handle.h"
#include <arpa/inet.h>
#include <errno.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint32_t level0_size = 0;
uint32_t GF = 0;
int main(int argc, char **argv)
{
	sConfig sconfig;
	sHandle shandle;

	/** parse/set options **/

	if (server_parse_argv_opts(&sconfig, argc, argv) < 0) {
		exit(errno);
	}

	printf("\033server's pid = %d\n", getpid());

	/** start server **/

	if ((server_handle_init(&shandle, sconfig)) < 0) {
		exit(errno);
	}

	if (server_print_config(shandle) < 0) {
		exit(errno);
	}

	if (server_spawn_threads(shandle) < 0) {
		exit(errno);
	} // blocking call!

	return EXIT_SUCCESS;
}
