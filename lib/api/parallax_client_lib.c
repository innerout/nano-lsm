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
#include "../btree/conf.h"
#include "../btree/set_options.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
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

struct par_handle {
	char *recv_buffer;
	char *send_buffer;
	pthread_mutex_t lock;
	uint64_t region_id;
	int sockfd;
	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;
};

struct par_net_header {
	uint32_t total_bytes;
	uint32_t opcode;
};

size_t par_net_header_calc_size(void)
{
	return sizeof(struct par_net_header);
}

static par_handle par_net_init(void)
{
	struct par_handle *handle = calloc(1UL, sizeof(struct par_handle));

	struct sockaddr_in server_addr;

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8080);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("TCP_CLIENT_SOCKET");
		log_error("Could not create socket");
		_exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("TCP_CLIENT_CONNECT");
		log_error("Could not connect to server");
		_exit(EXIT_FAILURE);
	}

	handle->sockfd = sockfd;
	handle->recv_buffer = calloc(1UL, KV_MAX_SIZE);
	handle->send_buffer = calloc(1UL, KV_MAX_SIZE);
	handle->recv_buffer_size = KV_MAX_SIZE;
	handle->send_buffer_size = KV_MAX_SIZE;

	return (par_handle)handle;
}

void par_net_handle_destroy(par_handle handle)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	free(parallax_handle->recv_buffer);
	free(parallax_handle->send_buffer);
	free(parallax_handle);
}

static ssize_t par_net_RPC(int sockfd, char *send_buffer, size_t send_buffer_len, char *recv_buffer,
			   size_t recv_buffer_len)
{
	struct msghdr msg = { 0 };
	struct iovec iov[1];

	iov[0].iov_base = send_buffer;
	iov[0].iov_len = send_buffer_len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t bytes_sent = sendmsg(sockfd, &msg, 0);
	if (bytes_sent < 0) {
		perror("TCP_CLIENT_SENDMSG");
		log_fatal("Sendmsg failed");
		close(sockfd);
		_exit(EXIT_FAILURE);
	}

	log_debug("Message bytes sent == %lu", bytes_sent);

	/* REPLY FROM SERVER */
	struct iovec iov_reply[1];
	struct msghdr msg_reply = { 0 };

	iov_reply[0].iov_base = recv_buffer;
	iov_reply[0].iov_len = recv_buffer_len;

	memset(&msg_reply, 0, sizeof(msg_reply));
	msg_reply.msg_iov = iov_reply;
	msg_reply.msg_iovlen = 1;

	ssize_t bytes_received = 0;
	bytes_received = recvmsg(sockfd, &msg_reply, 0);
	if (bytes_received < 0) {
		perror("recvmsg");
		_exit(EXIT_FAILURE);
	}

	log_debug("Total Reply size == %ld", bytes_received);

	return bytes_received;
}

char *par_format(char *device_name, uint32_t max_regions_num)
{
	(void)device_name;
	(void)max_regions_num;

	log_warn("par format not supported for the TCP client");
	return NULL;
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)par_net_init();

	size_t msg_len = par_net_open_req_calc_size(par_net_get_size(db_options->db_name)) + par_net_header_calc_size();

	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *request_header = (struct par_net_header *)(parallax_handle->send_buffer);
	request_header->total_bytes = msg_len;
	request_header->opcode = OPCODE_OPEN;

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
	struct par_net_open_req *request =
		par_net_open_req_create(db_options->create_flag, db_options->db_name,
					&parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);

	if (NULL == request) {
		log_fatal("Failed to create open request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return NULL;
	}

	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(reply_header->opcode == OPCODE_OPEN);

	par_handle ret_handle =
		par_net_open_rep_handle_reply(&parallax_handle->recv_buffer[par_net_header_calc_size()]);
	if (!ret_handle) {
		*error_message = "Operation (open) failed";
		par_net_handle_destroy(parallax_handle);
		return NULL;
	}
	parallax_handle->region_id = (uint64_t)ret_handle;

	return (par_handle)parallax_handle;
}

const char *par_close(par_handle handle)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_close_req_calc_size() + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
	header->total_bytes = msg_len;
	header->opcode = OPCODE_CLOSE;

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
	struct par_net_close_req *request = par_net_close_req_create(
		parallax_handle->region_id, &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
	if (NULL == request) {
		log_fatal("Failed to create close request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

	if (0 == bytes_received) {
		return "Error with sending buffer";
	}
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(reply_header->opcode == OPCODE_CLOSE);
	struct par_net_close_rep *reply =
		(struct par_net_close_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	const char *error_message = par_net_close_rep_handle_reply(reply);

	if (error_message) {
		return error_message;
	}

	par_net_handle_destroy(parallax_handle);
	return NULL;
}

// cppcheck-suppress unusedFunction
char *par_get_db_name(par_handle handle, const char **error_message)
{
	(void)handle;
	(void)error_message;
	return NULL;
}

enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)key_size;
	(void)value_size;
	(void)operation;
	(void)error_message;
	return 0;
}
//cppcheck-suppress constParameterPointer
struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;

	size_t msg_len =
		par_net_put_req_calc_size(key_value->k.size, key_value->v.val_size) + par_net_header_calc_size();

	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);

	header->total_bytes = msg_len;
	log_debug("PUT REQUEST: total_bytes are: %u", header->total_bytes);
	header->opcode = OPCODE_PUT;

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
	struct par_net_put_req *request = par_net_put_req_create(
		parallax_handle->region_id, key_value->k.size, key_value->k.data, key_value->v.val_size,
		key_value->v.val_buffer, &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
	if (NULL == request) {
		log_fatal("Failed to create put request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		struct par_put_metadata sample_return_value = { 0 };
		return sample_return_value;
	}
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(OPCODE_PUT == reply_header->opcode);
	struct par_net_put_rep *reply =
		(struct par_net_put_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];

	struct par_put_metadata metadata = par_net_put_rep_handle_reply(reply);

	return metadata;
}

struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	struct par_put_metadata sample_return_value = { 0 };
	(void)handle;
	(void)serialized_key_value;
	(void)error_message;
	(void)append_to_log;
	(void)abort_on_compaction;
	return sample_return_value;
}

// cppcheck-suppress constParameterPointer
void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_put_req_calc_size(key->size, value->val_size) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
	header->total_bytes = msg_len;
	header->opcode = OPCODE_GET;

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
	struct par_net_get_req *request =
		par_net_get_req_create(parallax_handle->region_id, key->size, key->data,
				       &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
	if (NULL == request) {
		log_fatal("Failed to create get request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return;
	}

	struct par_net_get_rep *reply =
		(struct par_net_get_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	if (par_net_get_rep_handle_reply(reply, value)) {
		*error_message = "Key Not found";
	}
}

void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message)
{
	struct key_splice *key = (struct key_splice *)key_serialized;
	struct par_key par_key = { .size = key_splice_get_key_size(key), .data = key_splice_get_key_offset(key) };
	par_get(handle, &par_key, value, error_message);

	if (*error_message) {
		log_fatal("%s", *error_message);
		_exit(EXIT_FAILURE);
	}
}

// cppcheck-suppress constParameterPointer
par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	par_ret_code ret_val = { 0 };
	(void)handle;
	(void)key;
	return ret_val;
}

// cppcheck-suppress unusedFunction
uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)handle;
	(void)buf;
	(void)buf_size;
	(void)IO_size;
	(void)log_cat;
	return 0;
}

uint64_t par_init_compaction_id(par_handle handle)
{
	(void)handle;
	return 0;
}

// cppcheck-suppress constParameterPointer
void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_del_req_calc_size(key->size) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
	header->total_bytes = msg_len;
	header->opcode = OPCODE_DEL;

	size_t buffer_len = parallax_handle->recv_buffer_size - par_net_header_calc_size();
	struct par_net_del_req *request =
		par_net_del_req_create(parallax_handle->region_id, key->size, key->data,
				       &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
	if (NULL == request) {
		log_fatal("Failed to create delete request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return;
	}
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(OPCODE_DEL == reply_header->opcode);
	struct par_net_del_rep *delete_reply =
		(struct par_net_del_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	par_net_del_rep_handle_reply(delete_reply);
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
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	par_scanner init = { 0 };
	(void)handle;
	(void)key;
	(void)mode;
	(void)error_message;
	return init;
}

void par_close_scanner(par_scanner sc)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)sc;
	return;
}

int par_get_next(par_scanner sc)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)sc;
	return 0;
}

int par_is_valid(par_scanner sc)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)sc;
	return 0;
}

struct par_key par_get_key(par_scanner sc)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	struct par_key key = { 0 };
	(void)sc;
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	struct par_value value = { 0 };
	(void)sc;
	return value;
}

// cppcheck-suppress unusedFunction
par_ret_code par_sync(par_handle handle)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	par_ret_code ret_val = { 0 };
	(void)handle;
	return ret_val;
}

struct par_options_desc *par_get_default_options(void)
{
	struct par_options_desc *default_db_options =
		(struct par_options_desc *)calloc(NUM_OF_CONFIGURATION_OPTIONS, sizeof(struct par_options_desc));

	// parse the options from options.yml config file
	struct lib_option *dboptions = NULL;
	parse_options(&dboptions);

	struct lib_option *option = NULL;
	/*get the default db option values */
	check_option(dboptions, "level0_size", &option);
	uint64_t level0_size = MB(option->value.count);

	check_option(dboptions, "growth_factor", &option);
	uint64_t growth_factor = option->value.count;

	check_option(dboptions, "level_medium_inplace", &option);
	uint64_t level_medium_inplace = option->value.count;

	check_option(dboptions, "medium_log_LRU_cache_size", &option);
	uint64_t LRU_cache_size = MB(option->value.count);

	check_option(dboptions, "gc_interval", &option);
	uint64_t gc_interval = option->value.count;

	check_option(dboptions, "primary_mode", &option);
	uint64_t primary_mode = option->value.count;

	check_option(dboptions, "replica_mode", &option);
	uint64_t replica_mode = 0;

	check_option(dboptions, "replica_build_index", &option);
	uint64_t replica_build_index = option->value.count;

	check_option(dboptions, "replica_send_index", &option);
	uint64_t replica_send_index = option->value.count;

	check_option(dboptions, "enable_bloom_filters", &option);
	uint64_t enable_bloom_filters = option->value.count;

	check_option(dboptions, "enable_compaction_double_buffering", &option);
	uint64_t enable_compaction_double_buffering = option->value.count;

	check_option(dboptions, "number_of_replicas", &option);
	uint64_t number_of_replicas = option->value.count;

	//fill default_db_options based on the default values
	default_db_options[LEVEL0_SIZE].value = level0_size;
	default_db_options[GROWTH_FACTOR].value = growth_factor;
	default_db_options[LEVEL_MEDIUM_INPLACE].value = level_medium_inplace;
	default_db_options[MEDIUM_LOG_LRU_CACHE_SIZE].value = LRU_cache_size;
	default_db_options[GC_INTERVAL].value = gc_interval;
	default_db_options[PRIMARY_MODE].value = primary_mode;
	default_db_options[REPLICA_MODE].value = replica_mode;
	default_db_options[ENABLE_BLOOM_FILTERS].value = enable_bloom_filters;
	default_db_options[ENABLE_COMPACTION_DOUBLE_BUFFERING].value = enable_compaction_double_buffering;
	default_db_options[NUMBER_OF_REPLICAS].value = number_of_replicas;
	default_db_options[REPLICA_BUILD_INDEX].value = replica_build_index;
	default_db_options[REPLICA_SEND_INDEX].value = replica_send_index;
	default_db_options[WCURSOR_SPIN_FOR_FLUSH_REPLIES].value = 0;

	return default_db_options;
}

void par_flush_superblock(par_handle handle)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)handle;
}
