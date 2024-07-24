#define _GNU_SOURCE
#include "server_handle.h"
#include "../par_net/par_net.h"
#include "allocator/djb2.h"
#include "btree/btree.h"
#include "btree/gc.h"
#include "btree/kv_pairs.h"
#include "parallax/parallax.h"
#include "parallax/structures.h"
#include <assert.h>

#include <arpa/inet.h>

#include <endian.h>
#include <errno.h>
// #include <linux/io_uring.h>
#include <linux/types.h>
#include <log.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <threads.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>

/*** defaults ***/

#define MAGIC_INIT_NUM (0xCAFEu)
#define EPOLL_MAX_EVENTS 64

#define PORT_MAX ((1L << 16) - 1L)

/*** server options ***/

#define DECIMAL_BASE 10

#define USAGE_STRING                              \
	"parallax_server: no options specified\n" \
	"try 'parallax_server --help' for more information\n"

#define HELP_STRING                                                                                \
	"Usage:\n  parallax_server <-bptf>\nOptions:\n"                                            \
	" -t, --threads <thread-num>  specify number of server threads.\n"                         \
	" -b, --bind <if-address>     specify the interface that the server will bind to.\n"       \
	" -p, --port <port>           specify the port that the server will be listening\n"        \
	" -f, --file <path>           specify the target (file of db) where parallax will run\n\n" \
	" -h, --help     display this help and exit\n"                                             \
	" -v, --version  display version information and exit\n"
#define NECESSARY_OPTIONS 6

#define VERSION_STRING "parallax_server 0.1\n"

#define ERROR_STRING "\033[1m[\033[31m*\033[0;1m]\033[0m"

#define CONFIG_STRING           \
	"[ Server Config ]\n"   \
	"  - threads = %u\n"    \
	"  - address = %s:%u\n" \
	"  - file = %s\n"       \
	"  - flags = not yet supported\n"

/** server argv[] options **/

struct server_options {
	__u16 magic_init_num;
	__u32 threadno;

	const char *paddr; // printable ip address
	const char *dbpath;

	struct sockaddr_storage inaddr; // ip address + port
};

/** server worker **/

struct worker {
	// par_handle par_handle;
	struct server_handle *shandle;
	pthread_t tid;

	__s32 epfd;
	__s32 sock;
	__u64 core;

	struct buffer buf;
	struct par_value pval;
};

/** server handle **/
#define MAX_PARALLAX_DBS 32
struct server_handle {
	__u16 magic_init_num;
	__u32 flags;
	__s32 sock;
	__s32 epfd;

	par_handle par_handle[MAX_PARALLAX_DBS];

	struct server_options *opts;
	struct worker *workers;
};

/** server request/reply **/

struct tcp_req {
	req_t type;
	kv_t kv;
	struct kv_splice_base kv_splice_base;
};

struct tcp_rep {
	retcode_t retc;
	struct par_value val;
};

struct server_handle *g_sh; // CTRL-C
_Thread_local const char *par_error_message_tl;

#define reset_errno() errno = 0
#define __offsetof_struct1(s, f) (__u64)(&((s *)(0UL))->f)

//#define req_is_invalid(req) ((__u32)(req->type) >= OPSNO)
//#define req_is_new_connection(req) (req->type == REQ_INIT_CONN)

#define infinite_loop_start() for (;;) {
#define infinite_loop_end() }
#define event_loop_start(index, limit) for (int index = 0; index < limit; ++index) {
#define event_loop_end() }

//#define reqbuf_hdr_read_type(req, buf) req->type = *((__u8 *)(buf))

//#define MAX_REGIONS 128

/***** private functions (decl) *****/

/**
 * @brief
 *
 * @param client_sock
 * @param worker
 * @return int
 */
/*
static int __client_version_check(int client_sock, struct worker *worker) __attribute__((nonnull(2)));
*/

/**
 * @brief
 *
 * @param this
 * @return int
 */
static int __handle_new_connection(struct worker *this) __attribute__((nonnull));


/**
 * @brief
 *
 * @param worker
 * @param client_sock
 * @param req
 * @return int
 */
/*
static tterr_e __req_recv(struct worker *restrict this, int client_sock, struct tcp_req *restrict req)
	__attribute__((nonnull(1, 3)));
*/

/**
 * @brief
 *
 * @param arg
 * @return void*
 */
static void *__handle_events(void *arg) __attribute__((nonnull));

static int __par_handle_req(struct worker *restrict this, int client_sock, struct tcp_req *restrict req)
	__attribute__((nonnull));

/**
 * @brief
 *
 */
/*
static void __parse_rest_of_header(char *restrict buf, struct tcp_req *restrict req) __attribute__((nonnull));
*/

/**
 * @brief
 *
 */
static int __pin_thread_to_core(int core);

/**
 * @brief
 *
 * @param server_handle
 * @param key_size
 * @param key
 * @return par_handle
 */
/*
static par_handle __server_handle_get_db(sHandle restrict server_handle, uint32_t key_size, char *restrict key)
	__attribute__((nonnull));
*/

/**
 * @brief
 *
 * @param signum
 */
static void server_sig_handler_SIGINT(int signum);

/***** public functions *****/

int server_parse_argv_opts(sConfig restrict *restrict sconfig, int argc, char *restrict *restrict argv)
{
	if (!sconfig) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	if (argc <= 1) {
		log_info(USAGE_STRING);
		exit(EXIT_FAILURE);
	}

	struct server_options *opts;
	int opt_sum = 0;

	if (!(*sconfig = calloc(1UL, sizeof(*opts))))
		return -(EXIT_FAILURE);

	opts = *sconfig;

	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-') {
			log_info(ERROR_STRING " parallax_server: unknown option '%s'\n", argv[i]);
			free(opts);
			exit(EXIT_FAILURE);
		}

		/*/
		* Both 'struct sockaddr_in' (IPv4) and 'struct sockaddr_in6' (IPv6) have the first two of their struct
		* fields identical. First comes the 'socket family' (2-Bytes) and then the 'port' (2-Bytes). As a
		* result of this, when setting either the port or the family, there is no problem to typecast
		* 'struct sockaddr_storage', which can store every address of every socket family in linux, to
		* any of 'struct sockaddr_in' or 'struct sockaddr_in6'. [/usr/include/netinet/in.h]
		/*/

		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--threads")) {
			reset_errno();
			long thrnum = strtol(argv[++i], NULL, DECIMAL_BASE);

			if (errno) {
				if (errno == EINVAL)
					log_info(ERROR_STRING " parallax_server: invalid number in option '%s'\n",
						 argv[i - 1U]);
				else
					log_info(ERROR_STRING " parallax_server: number out-of-range in option '%s'\n",
						 argv[i - 1U]);
				free(opts);
				exit(EXIT_FAILURE);
			}

			if (thrnum < 0) {
				log_info(ERROR_STRING " parallax_server: invalid number in option '%s'\n",
					 argv[i - 1U]);
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			opts->threadno = (unsigned int)thrnum;
		} else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
			reset_errno();
			long port = strtol(argv[++i], NULL, DECIMAL_BASE);

			if (errno) {
				if (errno == EINVAL)
					log_info(ERROR_STRING " parallax_server: invalid number in option '%s'\n",
						 argv[i - 1U]);
				else
					log_info(ERROR_STRING " parallax_server: number out-of-range in option '%s'\n",
						 argv[i - 1U]);

				free(opts);
				exit(EXIT_FAILURE);
			}

			if (port < 0) {
				fprintf(stderr, ERROR_STRING " parallax_server: invalid number in option '%s'\n",
					argv[i - 1U]);
				free(opts);
				exit(EXIT_FAILURE);
			} else if (port > PORT_MAX) {
				fprintf(stderr, ERROR_STRING " parallax_server: port is too big\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			((struct sockaddr_in *)(&opts->inaddr))->sin_port = htons((unsigned short)(port));
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " parallax_server: no address provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			int is_v6 = 0;

			for (int tmp = 0; argv[i][tmp]; ++tmp) // is this address IPv6?
			{
				if (argv[i][tmp] == ':') {
					is_v6 = 1;
					break;
				}
			}

			off64_t off;

			if (is_v6) {
				opts->inaddr.ss_family = AF_INET6;
				off = __offsetof_struct1(struct sockaddr_in6, sin6_addr);
			} else {
				opts->inaddr.ss_family = AF_INET;
				off = __offsetof_struct1(struct sockaddr_in, sin_addr);
			}

			if (!inet_pton(opts->inaddr.ss_family, argv[i], (char *)(&opts->inaddr) + off)) {
				fprintf(stderr, ERROR_STRING " parallax_server: invalid address\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			opts->paddr = argv[i];
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " parallax_server: no address provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}
			level0_size = strtoul(argv[i], NULL, 10);
			level0_size = MB(level0_size);
			++opt_sum;
			opts->paddr = argv[i];
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " parallax_server: no address provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}
			GF = strtoul(argv[i], NULL, 10);
			++opt_sum;
			opts->paddr = argv[i];
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
		help:
			fprintf(stdout, HELP_STRING);
			free(opts);
			exit(EXIT_SUCCESS);
		} else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			fprintf(stdout, VERSION_STRING);
			free(opts);
			exit(EXIT_SUCCESS);
		} else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " parallax_server: no file provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			opts->dbpath = argv[i];
		} else {
			fprintf(stderr, ERROR_STRING " parallax_server: uknown option '%s'\n", argv[i]);
			free(opts);
			exit(EXIT_FAILURE);
		}
	}

	if (opt_sum != NECESSARY_OPTIONS)
		goto help;

	opts->magic_init_num = MAGIC_INIT_NUM;

	return EXIT_SUCCESS;
}

int server_print_config(sHandle server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	struct server_handle *shandle = server_handle;

	if (shandle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	printf(CONFIG_STRING, shandle->opts->threadno, shandle->opts->paddr,
	       ntohs(((struct sockaddr_in *)(&shandle->opts->inaddr))->sin_port), shandle->opts->dbpath);

	return EXIT_SUCCESS;
}

int server_handle_init(sHandle restrict *restrict server_handle, sConfig restrict server_config)
{
	if (!server_handle || !server_config) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	struct server_options *sconf = server_config;

	if (sconf->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	/** END OF ERROR HANDLING **/

	if (!(*server_handle = malloc(sizeof(struct server_handle) + (sconf->threadno * sizeof(struct worker)))))
		return -(EXIT_FAILURE);

	struct server_handle *shandle = *server_handle;

	shandle->opts = sconf;
	shandle->workers = (struct worker *)((char *)(shandle) + sizeof(struct server_handle));
	shandle->sock = -1;
	shandle->epfd = -1;

	typeof(sconf->inaddr.ss_family) fam = sconf->inaddr.ss_family;

	if ((shandle->sock = socket(fam, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) < 0)
		goto cleanup;

	int opt = 1;
	setsockopt(shandle->sock, SOL_SOCKET, SO_REUSEADDR, &opt,
		   sizeof(opt)); /** TODO: remove, only for debug purposes! */

	if (bind(shandle->sock, (struct sockaddr *)(&sconf->inaddr),
		 (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
		goto cleanup;

	if (listen(shandle->sock, TT_MAX_LISTEN) < 0)
		goto cleanup;

	if ((shandle->epfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
		goto cleanup;

	struct epoll_event epev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT, .data.fd = shandle->sock };

	if (epoll_ctl(shandle->epfd, EPOLL_CTL_ADD, shandle->sock, &epev) < 0)
		goto cleanup;

	/** initialize parallax **/

	/* const char *error_message = par_format((char *)(sconf->dbpath), MAX_REGIONS);

	if (error_message) {
		return -(EXIT_FAILURE);
	}
	*/
	/*disable_gc();
	par_db_options db_options = { .volume_name = (char *)(sconf->dbpath), // fuck clang_format!
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "tcp_server_par.db",
				      .options = par_get_default_options() };
	db_options.options[LEVEL0_SIZE].value = level0_size;
	db_options.options[GROWTH_FACTOR].value = GF;
	log_info("Initializing tebis DBs with L0 %u and GF %u", level0_size, GF);
	char actual_db_name[128] = { 0 };
	for (int i = 0; i < MAX_PARALLAX_DBS; i++) {
		if (snprintf(actual_db_name, sizeof(actual_db_name), "tcp_server_par_%d", i) < 0) {
			//Insert Log
			return -(EXIT_FAILURE);
		}
		db_options.db_name = actual_db_name;
		shandle->par_handle[i] = par_open(&db_options, &error_message);
	}

	if (error_message) {
		//Insert Log
		return -(EXIT_FAILURE);
	} */

	signal(SIGINT, server_sig_handler_SIGINT);
	g_sh = shandle;

	shandle->magic_init_num = MAGIC_INIT_NUM;

	return EXIT_SUCCESS;

cleanup:
	close(shandle->sock);
	close(shandle->epfd);
	free(*server_handle);

	return -(EXIT_FAILURE);
}

int server_handle_destroy(sHandle server_handle)
{
	struct server_handle *shandle = server_handle;

	if (!server_handle || shandle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	/** END OF ERROR HANDLING **/

	// signal all threads to cancel

	close(shandle->sock);
	close(shandle->epfd);
	munmap(shandle->workers[0].buf.mem, shandle->opts->threadno * DEF_BUF_SIZE);
	free(shandle->opts);

	const char *error_message = par_close(shandle->par_handle);

	if (error_message) {
		//Insert Log
		return -(EXIT_FAILURE);
	}

	free(server_handle);

	return EXIT_SUCCESS;
}

int server_spawn_threads(sHandle server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	struct server_handle *shandle = server_handle;

	if (shandle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	/** END OF ERROR HANDLING **/

	__u32 threads = shandle->opts->threadno;

	if ((shandle->workers[0].buf.mem = mmap(NULL, threads * DEF_BUF_SIZE, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL)) == MAP_FAILED)
		return -(EXIT_FAILURE);

	__u32 index;

	for (index = 0U, --threads; index < threads; ++index) {
		shandle->workers[index].core = index;
		shandle->workers[index].sock = shandle->sock;
		shandle->workers[index].epfd = shandle->epfd;
		// shandle->workers[index].par_handle = shandle->par_handle;
		shandle->workers[index].shandle = shandle;
		shandle->workers[index].buf.bytes = DEF_BUF_SIZE;
		shandle->workers[index].buf.mem = shandle->workers[0].buf.mem + (index * DEF_BUF_SIZE);
		shandle->workers[index].pval.val_size = 0U;
		shandle->workers[index].pval.val_buffer_size = KV_MAX_SIZE;
		shandle->workers[index].pval.val_buffer =
			shandle->workers[index].buf.mem + TT_REPHDR_SIZE; // [!] one shared buffer per thread!

		if (pthread_create(&shandle->workers[index].tid, NULL, __handle_events,
				   shandle->workers + index)) { // one of the server threads failed!
			__u32 tmp;

			/* kill all threads that have been created by now */
			for (tmp = 0; tmp < index; ++tmp)
				pthread_cancel(shandle->workers[tmp].tid);

			for (tmp = 0; tmp < index; ++tmp)
				pthread_join(shandle->workers[tmp].tid, NULL);

			munmap(shandle->workers[0].buf.mem, threads * DEF_BUF_SIZE);

			return -(EXIT_FAILURE);
		}
	}

	// convert 'main()-thread' to 'server-thread'

	shandle->workers[index].core = index;
	shandle->workers[index].tid = pthread_self();
	shandle->workers[index].sock = shandle->sock;
	shandle->workers[index].epfd = shandle->epfd;
	// shandle->workers[index].par_handle = shandle->par_handle;
	shandle->workers[index].shandle = shandle;
	shandle->workers[index].buf.bytes = DEF_BUF_SIZE;
	shandle->workers[index].buf.mem = shandle->workers[0].buf.mem + (index * DEF_BUF_SIZE);
	shandle->workers[index].pval.val_size = 0U;
	shandle->workers[index].pval.val_buffer_size = KV_MAX_SIZE;
	shandle->workers[index].pval.val_buffer = shandle->workers[index].buf.mem + TT_REPHDR_SIZE;

	__handle_events(shandle->workers + index);

	return EXIT_SUCCESS;
}

/***** private functions *****/

static int __handle_new_connection(struct worker *this)
{
	struct sockaddr_storage caddr = { 0 };
	struct epoll_event epev = { 0 };

	socklen_t socklen = { 0 };
	int tmpfd = 0;

	if ((tmpfd = accept4(this->sock, (struct sockaddr *)(&caddr), &socklen, SOCK_CLOEXEC | SOCK_NONBLOCK)) < 0) {
		//Insert Log
		perror("Error is ");
		return -(EXIT_FAILURE);
	}

	epev.data.fd = tmpfd;
	epev.events = EPOLLIN | EPOLLONESHOT;

	if (epoll_ctl(this->epfd, EPOLL_CTL_ADD, tmpfd, &epev) < 0) {
		perror("__handle_new_connection::epoll_ctl(ADD)");
		close(tmpfd);

		return -(EXIT_FAILURE);
	}

	epev.events = EPOLLIN | EPOLLONESHOT;
	epev.data.fd = this->sock;

	/** rearm server socket **/

	if (epoll_ctl(this->epfd, EPOLL_CTL_MOD, this->sock, &epev) < 0) {
		//Insert Log

		epoll_ctl(this->epfd, EPOLL_CTL_DEL, tmpfd, NULL);
		close(this->sock);
		close(tmpfd);

		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/*
static int __client_version_check(int client_sock, struct worker *worker)
{
	__u32 version = be32toh(*((__u32 *)(worker->buf.mem + 1UL)));


	if (version != TT_VERSION) {
		errno = ECONNREFUSED;
		return -(EXIT_FAILURE);
	}

	if (send(client_sock, &version, sizeof(version), 0) < 0) {
		perror("__client_version_check::send()\n");

		errno = ECONNABORTED;
		return -(EXIT_FAILURE);
	}

	struct epoll_event epev = { .events = EPOLLIN | EPOLLONESHOT, .data.fd = client_sock };

	if (epoll_ctl(worker->epfd, EPOLL_CTL_MOD, client_sock, &epev) < 0) {
		perror("__client_version_check::epoll_ctl(MOD)");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
*/

/*
static void __parse_rest_of_header(char *restrict buf, struct tcp_req *restrict req)
{
	// steps:
	// 1. convert the header (in-buffer) from network-order to host-order*
	// 2. save header's contents inside
	// * parallax will use the same buffer using zero-copy!


	*((__u32 *)(buf + 1UL)) = be32toh(*((__u32 *)(buf + 1UL)));
	req->kv.key.size = *((__u32 *)(buf + 1UL));

	if (req->type == REQ_PUT) {
		*((__u32 *)(buf + 5UL)) = be32toh(*((__u32 *)(buf + 5UL)));
		req->kv.value.size = *((__u32 *)(buf + 5UL));
		req->kv.key.data = buf + 9UL;
		req->kv.value.data = (buf + 9UL) + req->kv.key.size;
	} else {
		req->kv.value.size = 0U;
		req->kv.value.data = NULL;
		req->kv.key.data = buf + 5UL;
	}
}
*/

/*
static tterr_e __req_recv(struct worker *restrict this, int client_sock, struct tcp_req *restrict req)
{
	__s64 ret = recv(client_sock, this->buf.mem, DEF_BUF_SIZE, 0);

	if (unlikely(ret < 0))
		return TT_ERR_GENERIC;

	reqbuf_hdr_read_type(req, this->buf.mem);

	if (unlikely(req_is_new_connection(req)))
		return __client_version_check(client_sock, this);

	if (unlikely(req_is_invalid(req)))
		return TT_ERR_NOT_SUP;

	__parse_rest_of_header(this->buf.mem, req);

	if (unlikely(!req->kv.key.size))
		return TT_ERR_ZERO_KEY;

	register __u64 off = ret;
	register __s64 bytes_left =
		(req->kv.key.size + req->kv.value.size + ((req->type == REQ_GET) ? 5UL : 9UL)) - ret;

	while (bytes_left) {
		ret = recv(client_sock, this->buf.mem + off, bytes_left, 0);

		if (unlikely(ret < 0))
			return TT_ERR_GENERIC;

		off += ret;
		bytes_left -= ret;
	}

	return TT_ERR_NONE;
}
*/
static void *__handle_events(void *arg)
{
	struct worker *this = arg;

	if (__pin_thread_to_core(this->core) < 0) {
		//Insert Log
		exit(EXIT_FAILURE);
	}

	uint32_t key_size = *(uint32_t *)(&this->buf.mem[1]);
	uint32_t value_size = *(uint32_t *)(&this->buf.mem[5]);
	struct tcp_req req = { .kv_splice_base.kv_cat = calculate_KV_category(key_size, value_size, insertOp),
			       .kv_splice_base.kv_splice = (void *)(this->buf.mem + 1UL) };

	int events;
	int client_sock;
	int event_bits;
	//int ret;

	struct epoll_event rearm_event = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT };
	struct epoll_event epoll_events[EPOLL_MAX_EVENTS];

	// pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	// push cleanup function (like at_exit())

	infinite_loop_start();

	events = epoll_wait(this->epfd, epoll_events, EPOLL_MAX_EVENTS, -1);

	if (unlikely(events < 0)) {
		//Insert Log
		continue;
	}

	event_loop_start(evindex, events);

	client_sock = epoll_events[evindex].data.fd;
	event_bits = epoll_events[evindex].events;

	if (event_bits & EPOLLRDHUP) {
		/** received FIN from client **/

		//Insert Log

		// the server can send some more packets here. If so, client code needs some changes

		shutdown(client_sock, SHUT_WR);
		//Insert Log

		epoll_ctl(this->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);
	} else if (likely(event_bits & EPOLLIN)) /** read event **/
	{
		/** new connection **/

		if (client_sock == this->sock) {
			//Insert Log

			if (__handle_new_connection(this) < 0)
				//Insert Log
				continue;
		}

		/** end **/

		/** request **/

		//ret = __req_recv(this, client_sock, &req);

		/*if (unlikely(ret == TT_ERR_CONN_DROP)) {
			//Insert Log
			goto client_error;
		}*/

		/*if (unlikely(ret == TT_ERR_GENERIC)) {
			//Insert Log
			goto client_error;
		}*/

		/*if (req.type == REQ_INIT_CONN)
			continue;

		if (unlikely(__par_handle_req(this, client_sock, &req) < 0L)) {
			//Insert Log
			goto client_error;
		}
		*/
		/* re-enable getting INPUT-events from the coresponding client */

		if (unlikely(__par_handle_req(this, client_sock, &req) < 0L)) {
			//Insert Log
			goto client_error;
		}

		rearm_event.data.fd = client_sock;
		epoll_ctl(this->epfd, EPOLL_CTL_MOD, client_sock, &rearm_event);

		continue;

	client_error:
		epoll_ctl(this->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);

	} else if (unlikely(event_bits & EPOLLERR)) /** error **/
	{
		//Insert Log
		/** TODO: error handling */
		continue;
	}

	event_loop_end();
	infinite_loop_end();

	__builtin_unreachable();
}

/*
static par_handle __server_handle_get_db(sHandle restrict server_handle, uint32_t key_size, char *restrict key)
{
	struct server_handle *shandle = server_handle;
	uint64_t hash_id = djb2_hash((unsigned char *)key, key_size);

	par_handle par_db = shandle->par_handle[hash_id % MAX_PARALLAX_DBS];
	// printf("Chose db %lu\n", hash_id % MAX_PARALLAX_DBS);
	return par_db;
}
*/

struct par_net_rep {
	uint32_t status;
} __attribute__((packed));

uint32_t par_find_opcode(char *buffer)
{
	uint32_t opcode;
	memcpy(&opcode, buffer, sizeof(uint32_t));

	if (opcode >= MAX_OPCODE)
		return 0;

	return opcode;
}

par_call par_net_call[6] = { NULL, par_net_call_open, par_net_call_put, par_net_call_del, par_net_call_get, par_net_call_close };

char *par_net_call_open(char *buffer, size_t *buffer_len)
{
	struct par_net_open_rep *reply;
	struct par_net_open_req *request = (struct par_net_open_req *)(buffer + sizeof(uint32_t));

	uint64_t opt_value = par_net_open_get_optvalue(request);
	uint8_t flag = par_net_open_get_flag(request);
	char *db_name = par_net_open_get_dbname(request);
	char *volume_name = par_net_open_get_volname(request);

	par_db_options db_options = { 0 };
	db_options.options = malloc(sizeof(struct par_options_desc));
	db_options.create_flag = flag;
	db_options.db_name = db_name;
	db_options.options->value = opt_value;
	db_options.volume_name = volume_name;

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);

	if (error_message) {
		log_fatal("%s", error_message);
		reply = par_net_open_rep_create(1, NULL, buffer_len);
		return (char *)reply;
	}

	free(db_options.options);

	reply = par_net_open_rep_create(0, handle, buffer_len);

	return (char *)reply;
}

char *par_net_call_put(char *buffer, size_t *buffer_len)
{
	struct par_net_put_rep *reply;
	struct par_net_put_req *request = (struct par_net_put_req *)(buffer + sizeof(uint32_t));

	uint64_t region_id = par_net_put_get_region_id(request);
	uint32_t key_size = par_net_put_get_key_size(request);
	uint32_t value_size = par_net_put_get_value_size(request);
	char *key_data = par_net_put_get_key(request);
	char *val_data = par_net_put_get_value(request);

	struct par_key_value kv = { 0 };
	kv.k.size = key_size;
	kv.k.data = key_data;
	kv.v.val_size = value_size;
	kv.v.val_buffer_size = value_size;
	kv.v.val_buffer = val_data;

	const char *error_message = NULL;
	struct par_put_metadata metadata;
	metadata = par_put((par_handle)(uintptr_t)region_id, &kv, &error_message);

	if (error_message) {
		log_fatal("%s", error_message);
		reply = par_net_put_rep_create(1, metadata, buffer_len);
		return (char *)reply;
	}

	reply = par_net_put_rep_create(0, metadata, buffer_len);
	return (char *)reply;
}

char *par_net_call_del(char *buffer, size_t *buffer_len)
{
	struct par_net_del_rep *reply;
	struct par_net_del_req *request = (struct par_net_del_req *)(buffer + sizeof(uint32_t));

	uint64_t region_id = par_net_del_get_region_id(request);
	uint32_t key_size = par_net_del_get_key_size(request);
	char *key_data = par_net_del_get_key(request);

	struct par_key key = { 0 };
	key.size = key_size;
	key.data = key_data;

	const char *error_message = NULL;
	par_delete((par_handle)(uintptr_t)region_id, &key, &error_message);

	if (error_message) {
		log_fatal("%s", error_message);
		reply = par_net_del_rep_create(1, buffer_len);
		return (char *)reply;
	}

	reply = par_net_del_rep_create(0, buffer_len);
	return (char *)reply;
}

char *par_net_call_get(char *buffer, size_t *buffer_len)
{
	struct par_net_get_rep *reply;
	struct par_net_get_req *request = (struct par_net_get_req *)(buffer + sizeof(uint32_t));

	uint64_t region_id = par_net_get_get_region_id(request);
	uint32_t key_size = par_net_get_get_key_size(request);
	uint32_t value_size = par_net_get_get_value_size(request);
	char *key_data = par_net_get_get_key(request);
	char *val_data = par_net_get_get_value(request);

	struct par_key k;
	struct par_value v;

	k.size = key_size;
	k.data = key_data;
	v.val_size = value_size;
	v.val_buffer_size = value_size;
	v.val_buffer = val_data;

	const char *error_message = NULL;
	par_get((par_handle)(uintptr_t)region_id, &k, &v, &error_message);

	if (error_message) {
		log_fatal("%s", error_message);
		reply = par_net_get_rep_create(1, buffer_len);
		return (char *)reply;
	}

	reply = par_net_get_rep_create(0, buffer_len);
	return (char *)reply;
}

char* par_net_call_close(char* buffer, size_t *buffer_len)
{
	struct par_net_close_rep *reply;
	struct par_net_close_req *request = (struct par_net_close_req *)(buffer + sizeof(uint32_t));

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)(uintptr_t)region_id;
	
	const char* return_string = par_close(handle);
	if(!return_string){
		log_fatal("Error in par_close");
		reply = par_net_close_rep_create(1, return_string, buffer_len);
		return (char*)reply;
	}

	reply = par_net_close_rep_create(0, return_string, buffer_len);
	return (char*)reply;
	
}

static int __par_handle_req(struct worker *restrict this, int client_sock, struct tcp_req *restrict req)
{
	(void)this;
	(void)req;
	char buffer[1024];
	struct iovec iov[1];
	struct msghdr msg;
	ssize_t bytes_received = 0;

	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	bytes_received = recvmsg(client_sock, &msg, 0);

	if (bytes_received < 0) {
		log_error("recvmsg failed");
		return EXIT_FAILURE;
	}
	log_info("message received");

	uint32_t opcode = par_find_opcode(msg.msg_iov->iov_base);

	if (opcode == 0)
		return EXIT_FAILURE;

	size_t rep_buffer_len = 0;
	char *reply = par_net_call[opcode](msg.msg_iov->iov_base, &rep_buffer_len);

	struct iovec iov_reply[1];
	struct msghdr msg_reply = { 0 };

	iov_reply[0].iov_base = reply;
	iov_reply[0].iov_len = rep_buffer_len;

	memset(&msg_reply, 0, sizeof(msg_reply));
	msg_reply.msg_iov = iov_reply;
	msg_reply.msg_iovlen = 1;

	ssize_t bytes_sent = sendmsg(client_sock, &msg_reply, 0);
	if (bytes_sent < 0) {
		log_error("sendmsg failed");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int __pin_thread_to_core(int core)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

/***** server signal handlers *****/

void server_sig_handler_SIGINT(int signum)
{
	printf("received \033[1;31mSIGINT (%d)\033[0m\n", signum);

	server_handle_destroy(g_sh);
	printf("\n");
	_Exit(EXIT_SUCCESS);
}