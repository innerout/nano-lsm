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
#include "../net_interface/par_net/par_net_scan.h"
#include "../scanner/scanner.h"

#include <arpa/inet.h>
#include <netdb.h>
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

struct par_handle {
	char *recv_buffer;
	char *send_buffer;
	pthread_mutex_t lock;
	uint64_t region_id;
	int sockfd;
	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;
	struct par_options_desc *configuration;
};

struct par_net_header {
	uint32_t total_bytes;
	uint32_t opcode;
};

size_t par_net_header_calc_size(void)
{
	return sizeof(struct par_net_header);
}

static bool par_split_hostname_port(const char *input, char **hostname, int *port)
{
	char *colon_pos = strchr(input, ':');
	if (colon_pos == NULL) {
		// No colon found in the input string
		return -1;
	}

	// Calculate the length of the hostname
	size_t hostname_len = colon_pos - input;

	// Allocate memory for the hostname and copy it
	*hostname = (char *)calloc(1UL, hostname_len + 1);
	if (*hostname == NULL) {
		return -1;
	}
	strncpy(*hostname, input, hostname_len);

	// Convert the port part to an integer using strtol
	char *endptr = NULL;
	long port_long = strtol(colon_pos + 1, &endptr, 10);

	// Check if the conversion was successful and the entire string was valid
	if (*endptr != '\0' || port_long < 0 || port_long > 65535) {
		free(*hostname);
		return false; // Invalid port number
	}

	*port = (int)port_long;

	return true;
}
/**
 * @brief Initializes connections to the Parallax server.
 * @param hostname pointer to the hostname of the server
 * in the form <hostname>:<port>
 * @return a new par_handle
 */
static par_handle par_net_init(const char *parallax_host)
{
	struct par_handle *handle = calloc(1UL, sizeof(struct par_handle));
	char *hostname = NULL;
	int port = 0;

	if (false == par_split_hostname_port(parallax_host, &hostname, &port)) {
		log_fatal("Failed to parse parallax server hostname: %s must be in <hostname>:<port> notation",
			  parallax_host);
		_exit(EXIT_FAILURE);
	}
	log_debug("Connecting to Parallax server: %s:%d", hostname, port);

	struct sockaddr_in server_addr = { 0 };
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	//Resolve IP from hostname
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	struct addrinfo hints = { 0 };
	struct addrinfo *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // AF_INET for IPv4

	if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
		log_fatal("Failed to resove host: %s to an IP!", hostname);
		perror("getaddrinfo failed");
		_exit(EXIT_FAILURE);
	}

	server_addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

	freeaddrinfo(res);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("TCP_CLIENT_SOCKET");
		log_error("Could not create socket");
		_exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("TCP_CLIENT_CONNECT");
		log_error("Could not connect to server: %s", parallax_host);
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

static ssize_t par_net_RPC(int sockfd, char *send_buffer, size_t send_buffer_len, char **recv_buffer,
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

	// log_debug("Message bytes sent == %lu", bytes_sent);

	/* REPLY FROM SERVER */
	struct iovec iov_reply[1];
	struct msghdr msg_reply = { 0 };

	iov_reply[0].iov_base = *recv_buffer;
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
	struct par_net_header *reply_header = (struct par_net_header *)*recv_buffer;
	if (bytes_received != reply_header->total_bytes) {
		log_debug(
			"Part of message received buffer was not enough to fit all shit bytes_received: %ld message is: %u going to expand it",
			bytes_received, reply_header->total_bytes);
		*recv_buffer = realloc(*recv_buffer, reply_header->total_bytes);
		iov_reply[0].iov_base = &(*recv_buffer)[bytes_received];
		iov_reply[0].iov_len = recv_buffer_len - bytes_received;

		memset(&msg_reply, 0, sizeof(msg_reply));
		msg_reply.msg_iov = iov_reply;
		msg_reply.msg_iovlen = 1;

		ssize_t extra_bytes_received = recvmsg(sockfd, &msg_reply, 0);
		assert(extra_bytes_received + bytes_received == reply_header->total_bytes);
	}

	// log_debug("Total Reply size == %ld", bytes_received);

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
	struct par_options_desc *configuration = par_get_default_options();
	struct par_handle *parallax_handle =
		(struct par_handle *)par_net_init((const char *)configuration[PARALLAX_SERVER].value);

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
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

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
	parallax_handle->configuration = configuration;

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
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

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
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

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
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
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
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

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
#define PAR_SCAN_MAX_KV_ENTRIES 50
#define PAR_SCAN_SEND_BUFFER_SIZE (2 * MAX_KEY_SIZE)
#define PAR_SCAN_RECV_BUFFER_SIZE (KV_MAX_SIZE * 4UL)
struct parallax_scanner {
	char *send_buffer;
	char *recv_buffer;
	struct par_handle *parallax_handle;
	uint32_t max_KV_pairs;
	uint32_t send_buffer_size;
	uint32_t recv_buffer_size;
	struct par_net_scan_rep *reply;
	bool is_valid;
};

static struct par_net_scan_rep *par_scan_get_next_batch(par_scanner scanner, par_seek_mode mode, struct par_key *key)
{
	struct parallax_scanner *parallax_scanner = scanner;
	size_t buffer_len = parallax_scanner->send_buffer_size - par_net_header_calc_size();

	struct par_net_scan_req *scan_req =
		par_net_scan_req_create(parallax_scanner->parallax_handle->region_id, key, PAR_SCAN_MAX_KV_ENTRIES,
					mode, &parallax_scanner->send_buffer[par_net_header_calc_size()], buffer_len);

	if (NULL == scan_req) {
		log_fatal("Failed to create scan request");
		_exit(EXIT_FAILURE);
	}

	// log_debug("Sending SCAN request to fetch next batch... %s mode with key: %.*s",
	// 	  mode == PAR_GREATER_OR_EQUAL ? "PAR_GREATER_OR_EQUAL" : "PAR_GREATER", key ? key->size : 4,
	// 	  key ? key->data : "NULL");

	struct par_net_header *header = (struct par_net_header *)parallax_scanner->send_buffer;
	header->opcode = OPCODE_SCAN;
	header->total_bytes = par_net_scan_req_calc_size(key ? key->size : 1) + sizeof(struct par_net_header);
	par_net_RPC(parallax_scanner->parallax_handle->sockfd, parallax_scanner->send_buffer, header->total_bytes,
		    &parallax_scanner->recv_buffer, parallax_scanner->recv_buffer_size);

	// log_debug("Sending SCAN request to fetch next batch ... D O N E");
	//-- reply part
	struct par_net_header *reply_header = (struct par_net_header *)parallax_scanner->recv_buffer;
	assert(reply_header->opcode == OPCODE_SCAN);
	struct par_net_scan_rep *reply =
		(struct par_net_scan_rep *)(&parallax_scanner->recv_buffer[par_net_header_calc_size()]);

	if (NULL == reply) {
		log_fatal("Got null scan reply?");
		_exit(EXIT_FAILURE);
	}
	parallax_scanner->is_valid = par_net_scan_rep_is_valid(reply);

	return reply;
}

// cppcheck-suppress constParameterPointer
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
	struct parallax_scanner *scanner = calloc(1UL, sizeof(struct parallax_scanner));
	scanner->send_buffer_size = PAR_SCAN_SEND_BUFFER_SIZE;
	scanner->recv_buffer_size = PAR_SCAN_RECV_BUFFER_SIZE;
	scanner->send_buffer = calloc(1UL, scanner->send_buffer_size);
	scanner->recv_buffer = calloc(1UL, scanner->recv_buffer_size);
	scanner->parallax_handle = handle;
	scanner->max_KV_pairs = PAR_SCAN_MAX_KV_ENTRIES;
	scanner->parallax_handle = handle;
	// log_debug("Requesting from server for the 1st batch of KV pairs... key is: %.*s", key == NULL ? 4 : key->size,
	// 	  key == NULL ? "NULL" : key->data);
	scanner->reply = par_scan_get_next_batch(scanner, mode, key);
	if (NULL == scanner->reply) {
		log_fatal("Failed to fetch 1st batch of KV pairs from the server");
		*error_message = "Failed to fetch 1st batch of KV pairs from the server";
		free(scanner);
		return NULL;
	}
	par_net_scan_rep_seek2_to_first(scanner->reply);
	return scanner;
}

void par_close_scanner(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = (struct parallax_scanner *)sc;
	free(parallax_scanner->send_buffer);
	free(parallax_scanner->recv_buffer);
	free(parallax_scanner);
}

int par_get_next(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = (struct parallax_scanner *)sc;
	assert(parallax_scanner->reply);

	if (false == par_net_scan_rep_seek2_next_splice(parallax_scanner->reply)) {
		struct kv_splice *last_splice = par_net_scan_rep_get_last_splice(parallax_scanner->reply);
		struct par_key key = { .size = kv_splice_get_key_size(last_splice),
				       .data = kv_splice_get_key_offset_in_kv(last_splice) };
		parallax_scanner->reply = par_scan_get_next_batch(parallax_scanner, PAR_GREATER, &key);
		return par_net_scan_rep_seek2_to_first(parallax_scanner->reply);
	}
	return true;
}

int par_is_valid(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = sc;
	return NULL == parallax_scanner->reply ? false : par_net_scan_rep_has_more(parallax_scanner->reply);
}

struct par_key par_get_key(par_scanner sc)
{
	struct par_key key = { 0 };
	struct parallax_scanner *parallax_scanner = sc;
	if (NULL == parallax_scanner->reply)
		return key;
	struct kv_splice *kv_splice = par_net_scan_rep_get_curr_splice(parallax_scanner->reply);
	key.size = kv_splice_get_key_size(kv_splice);
	key.data = kv_splice_get_key_offset_in_kv(kv_splice);
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_value value = { 0 };
	struct parallax_scanner *parallax_scanner = sc;
	if (NULL == parallax_scanner->reply)
		return value;
	struct kv_splice *kv_splice = par_net_scan_rep_get_curr_splice(parallax_scanner->reply);
	value.val_size = kv_splice_get_value_size(kv_splice);
	value.val_buffer = kv_splice_get_key_offset_in_kv(kv_splice);
	return value;
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
	// parse the options from options.yml config file
	struct lib_option *db_options = NULL;
	parse_options(&db_options);

	struct lib_option *option = NULL;
	/*get the default db option values */
	check_option(db_options, "level0_size", &option);
	uint64_t level0_size = MB(option->value.count);

	check_option(db_options, "growth_factor", &option);
	uint64_t growth_factor = option->value.count;

	check_option(db_options, "level_medium_inplace", &option);
	uint64_t level_medium_inplace = option->value.count;

	check_option(db_options, "medium_log_LRU_cache_size", &option);
	uint64_t LRU_cache_size = MB(option->value.count);

	check_option(db_options, "gc_interval", &option);
	uint64_t gc_interval = option->value.count;

	check_option(db_options, "primary_mode", &option);
	uint64_t primary_mode = option->value.count;

	check_option(db_options, "replica_mode", &option);
	uint64_t replica_mode = 0;

	check_option(db_options, "replica_build_index", &option);
	uint64_t replica_build_index = option->value.count;

	check_option(db_options, "replica_send_index", &option);
	uint64_t replica_send_index = option->value.count;

	check_option(db_options, "enable_bloom_filters", &option);
	uint64_t enable_bloom_filters = option->value.count;

	check_option(db_options, "enable_compaction_double_buffering", &option);
	uint64_t enable_compaction_double_buffering = option->value.count;

	check_option(db_options, "number_of_replicas", &option);
	uint64_t number_of_replicas = option->value.count;

	check_option(db_options, "parallax_server", &option);
	const char *parallax_server = strdup(option->value.name);

	struct par_options_desc *default_db_options =
		(struct par_options_desc *)calloc(NUM_OF_CONFIGURATION_OPTIONS, sizeof(struct par_options_desc));
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
	default_db_options[PARALLAX_SERVER].value = (uint64_t)parallax_server;
	log_debug("PARALLAX_SERVER_HOSTNAME is: %s", parallax_server);
	destroy_options(db_options);
	return default_db_options;
}

void par_flush_superblock(par_handle handle)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)handle;
}
