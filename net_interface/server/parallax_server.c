#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"
#include <stdio.h>

#include "server_handle.h"
#include <arpa/inet.h>
#include <errno.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct server_options *server_options = server_parse_argv_opts(argc, argv);

	struct server_handle *server_handle = server_handle_init(server_options);
	if (NULL == server_handle) {
		log_fatal("Failed to initialize server");
		_exit(EXIT_FAILURE);
	}

	if (server_print_config(server_handle) < 0) {
		_exit(errno);
	}

	if (server_spawn_threads(server_handle) < 0) {
		_exit(errno);
	}

	return EXIT_SUCCESS;
}
