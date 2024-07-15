// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "../allocator/kv_format.h"
#include "../allocator/log_structures.h"
#include "../allocator/persistent_operations.h"
#include "../allocator/region_log.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../btree/set_options.h"
#include "../common/common.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include "../lib/allocator/device_structures.h"
#include "../lib/scanner/scanner_mode.h"
#include "../net_interface/par_net/par_net.h"
#include "../net_interface/par_net/par_net_open.h"
#include "../net_interface/par_net/par_net_put.h"
#include "../scanner/scanner.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256

static int par_net_send(char *buffer, size_t *buffer_len)
{
	int sockfd;
	struct sockaddr_in server_addr;

	struct msghdr msg = { 0 };
	struct iovec iov[1];
	ssize_t bytes_sent;

	iov[0].iov_base = buffer;
	iov[0].iov_len = *buffer_len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8080);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("TCP_CLIENT_SOCKET");
		log_error("Could not create socket");
		return 1;
	}

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("TCP_CLIENT_CONNECT");
		log_error("Could not connect to server");
		_exit(EXIT_FAILURE);
	}

	bytes_sent = sendmsg(sockfd, &msg, 0);
	if (bytes_sent < 0) {
		perror("TCP_CLIENT_SENDMSG");
		log_fatal("Sendmsg failed");
		close(sockfd);
		_exit(EXIT_FAILURE);
	}

	close(sockfd);

	return 0;
}

char *par_format(char *device_name, uint32_t max_regions_num)
{
	return NULL;
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
	uint32_t name_size = get_size(db_options->db_name);
	uint32_t volume_name_size = get_size(db_options->volume_name);
	size_t buffer_len = par_net_open_calc_size(name_size, volume_name_size);
	buffer_len += sizeof(uint32_t);
	char *buffer = malloc(buffer_len);

	uint32_t opcode = OPCODE_OPEN;
	buffer[0] = opcode;

	struct par_net_open_req *request =
		par_net_open_req_create(db_options->create_flag, name_size, db_options->db_name, volume_name_size,
					db_options->volume_name, db_options->options->value, buffer, &buffer_len);

	char *serialized_buffer = (char *)request - sizeof(uint32_t);

	if (par_net_send(serialized_buffer, &buffer_len) == 1) {
		*error_message = "Could not send to server";
		return NULL;
	}
}

const char *par_close(par_handle handle)
{
	return NULL;
}

// cppcheck-suppress unusedFunction
char *par_get_db_name(par_handle handle, const char **error_message)
{
	return NULL;
}

enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message)
{
	return 0;
}
//cppcheck-suppress constParameterPointer
struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	struct par_put_metadata sample_return_value = { 0 };

	size_t buffer_len = par_net_put_calc_size(key_value->k.size, key_value->v.val_size);
	buffer_len += sizeof(uint32_t);
	char *buffer = malloc(buffer_len);

	uint32_t opcode = OPCODE_PUT;
	buffer[0] = opcode;

	struct par_net_put_req *request = par_net_put_req_create(*(uint64_t *)handle, key_value->k.size,
								 key_value->k.data, key_value->v.val_size,
								 key_value->v.val_buffer, buffer, &buffer_len);

	char *serialized_buffer = (char *)request - sizeof(uint32_t);

	if (par_net_send(serialized_buffer, &buffer_len) == 1) {
		*error_message = "Could not send to server";
		return sample_return_value;
	}

	return sample_return_value;
}

struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction)
{
}

// cppcheck-suppress constParameterPointer
void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
}

void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message)
{
	return;
}

// cppcheck-suppress constParameterPointer
par_ret_code par_exists(par_handle handle, struct par_key *key)
{
}

// cppcheck-suppress unusedFunction
uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat)
{
	return 0;
}

uint64_t par_init_compaction_id(par_handle handle)
{
	return 0;
}

// cppcheck-suppress constParameterPointer
void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	size_t buffer_len = par_net_del_calc_size(key->size);
	buffer_len += sizeof(uint32_t);
	char *buffer = malloc(buffer_len);

	uint32_t opcode = OPCODE_DEL;
	buffer[0] = opcode;

	struct par_net_del_req *request =
		par_net_del_req_create(*(uint64_t *)handle, key->size, key->data, buffer, &buffer_len);

	char *serialized_buffer = (char *)request - sizeof(uint32_t);

	if (par_net_send(serialized_buffer, &buffer_len) == 1) {
		*error_message = "Could not send to server";
		return;
	}

	return;
}

/*scanner staff*/

struct par_scanner {
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	struct scanner *sc;
	uint32_t buf_size;
	uint16_t allocated;
	uint16_t valid;
	char *kv_buf;
};

// cppcheck-suppress constParameterPointer
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
	return NULL;
}

void par_close_scanner(par_scanner sc)
{
	return;
}

int par_get_next(par_scanner sc)
{
	return 0;
}

int par_is_valid(par_scanner sc)
{
	return 0;
}

struct par_key par_get_key(par_scanner sc)
{
	struct par_key key = { 0, NULL };
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_value value = { 0, 0, NULL };
	return value;
}

// cppcheck-suppress unusedFunction
par_ret_code par_sync(par_handle handle)
{
}

/**
 * Create, populate and return a buffer containing the default db_options values from option.yml file. Callers can modify the buffer at will.
 * @retval Array with NUM_OF_OPTIONS sizeo of struct options_desc
 */
struct par_options_desc *par_get_default_options(void)
{
}

void par_flush_superblock(par_handle handle)
{
	return;
}
