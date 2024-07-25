#define _GNU_SOURCE
#include "../par_net/par_net.h"
#include "server_handle.h"
#include "../allocator/djb2.h"
#include "btree/btree.h"
#include "btree/kv_pairs.h"
#include "parallax/parallax.h"
#include "parallax/structures.h"
#include "tcp_errors.h"
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <log.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef SSL
#include "../common/common_ssl/mbedtls_utility.h"
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#ifdef SGX
#include <openenclave/enclave.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <uthash.h>
#endif
/*** defaults ***/

#define MAGIC_INIT_NUM (0xCAFEu)
#define EPOLL_MAX_EVENTS 64

#define PORT_MAX ((1L << 16) - 1L)

/*** server options ***/
#define DECIMAL_BASE 10

#define USAGE_STRING                         \
	"tcp-server: no options specified\n" \
	"try 'tcp-server --help' for more information\n"

#define HELP_STRING                                                                                             \
	"Usage:\n  tcp-server <-bptf>\nOptions:\n"                                                              \
	" -t, --threads <thread-num>  specify number of server threads.\n"                                      \
	" -b, --bind <if-address>     specify the interface that the server will "                              \
	"bind to.\n"                                                                                            \
	" -p, --port <port>           specify the port that the server will be "                                \
	"listening\n"                                                                                           \
	" -f, --file <path>           specify the target (file of db) where "                                   \
	"parallax will run\n\n"                                                                                 \
	" -L0, --L0_size <size in MB>           sets the L0 size in MB of each region in Parallax\n\n"          \
	" -GF, --GF <growth factor>           specify the growth factor of levels in each Parallax region\n\n " \
	" -h, --help     display this help and exit\n"                                                          \
	" -v, --version  display version information and exit\n"                                                \
  " -pf, --par_format           (Optional) specify whether database should be formatted\n"                

#define NECESSARY_OPTIONS 6

#define VERSION_STRING "tcp-server 0.1\n"

#define ERROR_STRING "\033[1m[\033[31m*\033[0;1m]\033[0m"

#define CONFIG_STRING           \
	"[ Server Config ]\n"   \
	"  - threads = %u\n"    \
	"  - address = %s:%u\n" \
	"  - file = %s\n"       \
	"  - flags = not yet supported\n"

/** server argv[] options **/

struct server_options {
	uint16_t magic_init_num;
	uint32_t threadno;

	const char *paddr; // printable ip address
	long port;
	const char *dbpath;

	struct sockaddr_storage inaddr; // ip address + port
  
  uint8_t format;
};

/** server worker **/

struct worker {
	// par_handle par_handle;
	struct server_handle *shandle;
	pthread_t tid;

	int32_t epfd;
	int32_t sock;
	uint64_t core;

	struct buffer buf;
	struct par_value pval;
};

#ifdef SSL
struct conn_info {
	int32_t fd;
	mbedtls_ssl_context *ssl_session;
	mbedtls_net_context *client_fd;
	UT_hash_handle hh;
};
#endif

/** server handle **/
#define MAX_PARALLAX_DBS 1
struct server_handle {
	uint16_t magic_init_num;
	uint32_t flags;
	int32_t sock;
	int32_t epfd;

	par_handle par_handle[MAX_PARALLAX_DBS];

	struct server_options *opts;
	struct worker *workers;
#ifdef SSL
	mbedtls_net_context listen_fd;
	struct conn_info *conn_ht;
	pthread_rwlock_t lock;
#endif
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
#define __offsetof_struct1(s, f) (uint64_t)(&((s *)(0UL))->f)

#define infinite_loop_start() for (;;) {
#define infinite_loop_end() }
#define event_loop_start(index, limit) for (int index = 0; index < limit; ++index) {
#define event_loop_end() }

//#define reqbuf_hdr_read_type(req, buf) req->type = *((uint8_t *)(buf))

#define MAX_REGIONS 128

/***** private functions (decl) *****/
#ifdef SSL
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}
#endif

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
#ifndef SSL
static int __pin_thread_to_core(int core);
#endif

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
		fprintf(stderr, USAGE_STRING);
		exit(EXIT_FAILURE);
	}

	struct server_options *opts;
	int opt_sum = 0;

	if (!(*sconfig = calloc(1UL, sizeof(*opts))))
		return -(EXIT_FAILURE);

	opts = *sconfig;
  
	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-') {
			fprintf(stderr, ERROR_STRING " tcp-server: uknown option '%s'\n", argv[i]);
			free(opts);
			exit(EXIT_FAILURE);
		}

		/*/
     * Both 'struct sockaddr_in' (IPv4) and 'struct sockaddr_in6' (IPv6) have
     * the first two of their struct fields identical. First comes the 'socket
     * family' (2-Bytes) and then the 'port' (2-Bytes). As a result of this,
     * when setting either the port or the family, there is no problem to
     * typecast 'struct sockaddr_storage', which can store every address of
     * every socket family in linux, to any of 'struct sockaddr_in' or 'struct
     * sockaddr_in6'. [/usr/include/netinet/in.h]
     */

		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--threads")) {
			reset_errno();
			long thrnum = strtol(argv[++i], NULL, DECIMAL_BASE);

			if (errno) {
				if (errno == EINVAL)
					fprintf(stderr, ERROR_STRING " tcp-server: invalid number in option '%s'\n",
						argv[i - 1U]);
				else
					fprintf(stderr,
						ERROR_STRING " tcp-server: number out-of-range in option '%s'\n",
						argv[i - 1U]);

				free(opts);
				exit(EXIT_FAILURE);
			}

			if (thrnum < 0) {
				fprintf(stderr, ERROR_STRING " tcp-server: invalid number in option '%s'\n",
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
					fprintf(stderr, ERROR_STRING " tcp-server: invalid number in option '%s'\n",
						argv[i - 1U]);
				else
					fprintf(stderr,
						ERROR_STRING " tcp-server: number out-of-range in option '%s'\n",
						argv[i - 1U]);

				free(opts);
				exit(EXIT_FAILURE);
			}

			if (port < 0) {
				fprintf(stderr, ERROR_STRING " tcp-server: invalid number in option '%s'\n",
					argv[i - 1U]);
				free(opts);
				exit(EXIT_FAILURE);
			} else if (port > PORT_MAX) {
				fprintf(stderr, ERROR_STRING " tcp-server: port is too big\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			((struct sockaddr_in *)(&opts->inaddr))->sin_port = htons((unsigned short)(port));
			opts->port = port;
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " tcp-server: no address provided!\n");
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

			off_t off;

			if (is_v6) {
				opts->inaddr.ss_family = AF_INET6;
				off = __offsetof_struct1(struct sockaddr_in6, sin6_addr);
			} else {
				opts->inaddr.ss_family = AF_INET;
				off = __offsetof_struct1(struct sockaddr_in, sin_addr);
			}

			if (!inet_pton(opts->inaddr.ss_family, argv[i], (char *)(&opts->inaddr) + off)) {
				fprintf(stderr, ERROR_STRING " tcp-server: invalid address\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			opts->paddr = argv[i];
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " tcp-server: no address provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}
			level0_size = strtoul(argv[i], NULL, 10);
			level0_size = MB(level0_size);
			++opt_sum;
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			if (!argv[++i]) {
				fprintf(stderr, ERROR_STRING " tcp-server: no address provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}
			GF = strtoul(argv[i], NULL, 10);
			++opt_sum;
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
				fprintf(stderr, ERROR_STRING " tcp-server: no file provided!\n");
				free(opts);
				exit(EXIT_FAILURE);
			}

			++opt_sum;
			opts->dbpath = argv[i];
		} else if (!strcmp(argv[i], "-pf") ||!strcmp(argv[i], "--par_format")){
       opts->format = 1; 
    }else {
			fprintf(stderr, ERROR_STRING " tcp-server: uknown option '%s'\n", argv[i]);
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

#ifdef SSL
int configure_server_ssl(mbedtls_ssl_config *conf, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *server_cert,
			 mbedtls_pk_context *pkey)
{
	int ret = 1;

	ret = generate_certificate_and_pkey(server_cert, pkey);
	if (ret != 0) {
		log_fatal("generate_certificate_and_pkey failed with %d\n", ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		log_fatal("mbedtls_ssl_config_defaults returned %d\n", ret);
		goto exit;
	}

	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
	mbedtls_ssl_conf_dbg(conf, my_debug, stdout);

	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

	if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0) {
		log_fatal("mbedtls_ssl_conf_own_cert returned %d\n", ret);
		goto exit;
	}

	ret = 0;
exit:
	fflush(stdout);
	return ret;
}
#endif

#ifdef SSL
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_x509_crt server_cert;
mbedtls_pk_context pkey;
const char *pers = "tls_server";
#endif

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
#ifdef SSL
	if (pthread_rwlock_init(&shandle->lock, NULL) != 0) {
		return -(EXIT_FAILURE);
	}

	/* Load host resolver and socket interface modules explicitly */
#ifdef SGX
	if (load_oe_modules() != OE_OK) {
		log_fatal("loading required Open Enclave modules failed\n");
		goto cleanup;
	}
#endif

	shandle->conn_ht = NULL;
	// init mbedtls objects
	int ret = 0;
	char port_str[10];
	sprintf(port_str, "%ld", sconf->port);
	mbedtls_net_init(&shandle->listen_fd);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&server_cert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
#ifdef SGX
	oe_verifier_initialize();
#endif

	if ((ret = mbedtls_net_bind(&shandle->listen_fd, sconf->paddr, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
		log_fatal("mbedtls_net_bind returned %d\n", ret);
		goto cleanup;
	}
	shandle->sock = shandle->listen_fd.fd;
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		log_fatal("mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto cleanup;
	}
	// Configure server SSL settings
	ret = configure_server_ssl(&conf, &ctr_drbg, &server_cert, &pkey);
	if (ret != 0) {
		log_fatal("configure_server_ssl returned %d\n", ret);
		goto cleanup;
	}
#else
	sa_family_t fam = sconf->inaddr.ss_family;

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
#endif
	if ((shandle->epfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
		goto cleanup;

	struct epoll_event epev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT, .data.fd = shandle->sock };

	if (epoll_ctl(shandle->epfd, EPOLL_CTL_ADD, shandle->sock, &epev) < 0) {
		log_fatal("epoll_ctl failed");
		goto cleanup;
	}

	/** initialize parallax **/
  if(shandle->opts->format){
    log_info("Format option enabled");
	  const char *error_message = par_format((char *)(sconf->dbpath), MAX_REGIONS);
    
	  if (error_message) {
		  log_fatal("%s", error_message);
		  return -(EXIT_FAILURE);
	  }

  }else{
    log_info("Format option not enabled");
  }
  signal(SIGINT, server_sig_handler_SIGINT);
	g_sh = shandle;

	shandle->magic_init_num = MAGIC_INIT_NUM;

	return EXIT_SUCCESS;

cleanup:
#ifdef SSL
	mbedtls_net_free(&shandle->listen_fd);
	mbedtls_x509_crt_free(&server_cert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#ifdef SGX
	oe_verifier_shutdown();
#endif
#endif
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
#ifdef SSL
	mbedtls_net_free(&shandle->listen_fd);
	mbedtls_x509_crt_free(&server_cert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#ifdef SGX
	oe_verifier_shutdown();
#endif
#endif

	close(shandle->sock);
	close(shandle->epfd);
	munmap(shandle->workers[0].buf.mem, shandle->opts->threadno * DEF_BUF_SIZE);
	free(shandle->opts);

	const char *error_message = par_close(shandle->par_handle);

	if (error_message) {
		log_fatal("%s", error_message);
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

	uint32_t threads = shandle->opts->threadno;

	if ((shandle->workers[0].buf.mem = mmap(NULL, threads * DEF_BUF_SIZE, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL)) == MAP_FAILED)
		return -(EXIT_FAILURE);

	uint32_t index;

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
			uint32_t tmp;

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
	// struct sockaddr_storage caddr = { 0 };
	struct epoll_event epev = { 0 };

	// socklen_t socklen = { 0 };
	int tmpfd = 0;

	if (fcntl(this->sock, F_SETFL, O_NONBLOCK) == -1) {
		perror("fcntl nonblock failure");
		return -(EXIT_FAILURE);
	}

	if (fcntl(this->sock, F_SETFD, FD_CLOEXEC) == -1) {
		perror("fcntl cloexec failure");
		return -(EXIT_FAILURE);
	}
#ifdef SSL
	int ret;
	mbedtls_ssl_context *ssl_session = malloc(sizeof(mbedtls_ssl_context));
	if (ssl_session == NULL) {
		return -(EXIT_FAILURE);
	}
	mbedtls_ssl_init(ssl_session);
	if ((ret = mbedtls_ssl_setup(ssl_session, &conf)) != 0) {
		log_fatal("mbedtls_ssl_setup returned %d\n", ret);
		free(ssl_session);
		return -(EXIT_FAILURE);
	}
	mbedtls_net_context *client_fd = malloc(sizeof(mbedtls_net_context));
	if (client_fd == NULL) {
		log_fatal("malloc of mbedtls_net_context failed");
		return -(EXIT_FAILURE);
	}
	if ((tmpfd = mbedtls_net_accept(&this->shandle->listen_fd, client_fd, NULL, 0, NULL)) < 0) {
		log_fatal("mbedtls_net_accept failed with %s", strerror(errno));
		free(ssl_session);
		free(client_fd);
		return -(EXIT_FAILURE);
	}
	tmpfd = client_fd->fd;
	mbedtls_net_set_nonblock(client_fd);
	mbedtls_ssl_set_bio(ssl_session, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	while ((ret = mbedtls_ssl_handshake(ssl_session)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_CONN_EOF) {
			free(ssl_session);
			free(client_fd);
			return -(EXIT_FAILURE);
		}
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			log_fatal("mbedtls_ssl_handshake returned -0x%x\n", -ret);
			free(ssl_session);
			free(client_fd);
			return -(EXIT_FAILURE);
		}
	}

	/*Add (fd, ssl_session) pair to ht*/
	struct conn_info *conn_info = malloc(sizeof(struct conn_info));
	if (conn_info == NULL)
		exit(EXIT_FAILURE);
	conn_info->fd = client_fd->fd;
	conn_info->ssl_session = ssl_session;
	conn_info->client_fd = client_fd;
	if (pthread_rwlock_wrlock(&this->shandle->lock) != 0)
		exit(EXIT_FAILURE);
	HASH_ADD_INT(this->shandle->conn_ht, fd, conn_info);
	pthread_rwlock_unlock(&this->shandle->lock);

#else
	if ((tmpfd = accept(this->sock, NULL, NULL)) < 0) {
		log_fatal("%s", strerror(errno));
		perror("Error is ");
		return -(EXIT_FAILURE);
	}
#endif

	epev.data.fd = tmpfd;
	epev.events = EPOLLIN | EPOLLONESHOT;

	if (epoll_ctl(this->epfd, EPOLL_CTL_ADD, tmpfd, &epev) < 0) {
		perror("__handle_new_connection::epoll_ctl(ADD)");
		close(tmpfd);
#ifdef SSL
		free(ssl_session);
		free(client_fd);
#endif
		return -(EXIT_FAILURE);
	}

	epev.events = EPOLLIN | EPOLLONESHOT;
	epev.data.fd = this->sock;
	/** rearm server socket **/

	if (epoll_ctl(this->epfd, EPOLL_CTL_MOD, this->sock, &epev) < 0) {
		log_fatal("epoll_ctl(): %s ---> terminating server!!!", strerror(errno));

		epoll_ctl(this->epfd, EPOLL_CTL_DEL, tmpfd, NULL);
		close(this->sock);
		close(tmpfd);
#ifdef SSL
		free(ssl_session);
		free(client_fd);
#endif
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}

static void *__handle_events(void *arg)
{
	struct worker *this = arg;
#ifndef SSL
	if (__pin_thread_to_core(this->core) < 0) {
		log_fatal("__pin_thread_to_core(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif

	/*
          uint32_t key_size = *(uint32_t *)(&this->buf.mem[1]);
          uint32_t value_size = *(uint32_t *)(&this->buf.mem[5]);
          struct tcp_req req = { .kv_splice_base.kv_cat =
     calculate_KV_category(key_size, value_size, insertOp),
                                 .kv_splice_base.kv_splice = (void
     *)(this->buf.mem + 1UL) };
  */
	struct tcp_req req = { 0 };

	int events;
	int client_sock;
	int event_bits;

	struct epoll_event rearm_event = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT };
	struct epoll_event epoll_events[EPOLL_MAX_EVENTS];

	// pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	// push cleanup function (like at_exit())

	infinite_loop_start();

	events = epoll_wait(this->epfd, epoll_events, EPOLL_MAX_EVENTS, -1);

	if (unlikely(events < 0)) {
		log_fatal("epoll(): %s", strerror(errno));
		continue;
	}

	event_loop_start(evindex, events);

	client_sock = epoll_events[evindex].data.fd;
	event_bits = epoll_events[evindex].events;

	if (event_bits & EPOLLRDHUP) {
		/** received FIN from client **/

		log_info("client (%d) wants to terminate the connection", client_sock);

		// the server can send some more packets here. If so, client code needs some
		// changes

		shutdown(client_sock, SHUT_WR);
		log_info("terminating connection with client(%d)", client_sock);

		epoll_ctl(this->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);
#ifdef SSL
		struct conn_info *conn_info;
		if (pthread_rwlock_wrlock(&this->shandle->lock) != 0) {
			continue;
		}
		HASH_FIND_INT(this->shandle->conn_ht, &client_sock, conn_info);
		free(conn_info->ssl_session);
		free(conn_info->client_fd);
		HASH_DEL(this->shandle->conn_ht, conn_info);
		pthread_rwlock_unlock(&this->shandle->lock);
#endif
	} else if (likely(event_bits & EPOLLIN)) /** read event **/
	{
		/** new connection **/
		if (client_sock == this->sock) {
			log_info("new connection");

			if (__handle_new_connection(this) < 0)
				log_fatal("__handle_new_connection() failed: %s\n", strerror(errno));

			continue;
		}

		/** end **/

		/** request **/
		if (unlikely(__par_handle_req(this, client_sock, &req) < 0L)) {
			log_fatal("__par_handle_req(): %s", strerror(errno));
			goto client_error;
		}

		/* re-enable getting INPUT-events from the coresponding client */

		rearm_event.data.fd = client_sock;
		epoll_ctl(this->epfd, EPOLL_CTL_MOD, client_sock, &rearm_event);

		continue;

	client_error:
		epoll_ctl(this->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);
#ifdef SSL
		struct conn_info *conn_info;
		if (pthread_rwlock_wrlock(&this->shandle->lock) != 0) {
			continue;
		}
		HASH_FIND_INT(this->shandle->conn_ht, &client_sock, conn_info);
		free(conn_info->ssl_session);
		free(conn_info->client_fd);
		HASH_DEL(this->shandle->conn_ht, conn_info);
		pthread_rwlock_unlock(&this->shandle->lock);
#endif
	} else if (unlikely(event_bits & EPOLLERR)) /** error **/
	{
		log_fatal("events[%d] = EPOLLER, fd = %d\n", evindex, client_sock);
		/** TODO: error handling */
		continue;
	}

	event_loop_end();
	infinite_loop_end();

	__builtin_unreachable();
}

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

#ifndef SSL
static int __pin_thread_to_core(int core)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}
#endif

/***** server signal handlers *****/

void server_sig_handler_SIGINT(int signum)
{
	printf("received \033[1;31mSIGINT (%d)\033[0m\n", signum);

	server_handle_destroy(g_sh);
	printf("\n");
	_Exit(EXIT_SUCCESS);
}

