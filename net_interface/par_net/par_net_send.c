#include "par_net.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int par_net_send(char *buffer, size_t *buffer_len)
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
	server_addr.sin_port = 12345;

	if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
		perror("inet_pton");
		exit(EXIT_FAILURE);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0) < 0)) {
		log_error("Could not create socket");
		return 1;
	}

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		log_error("Could not connect to server");
		return 1;
	}

	bytes_sent = sendmsg(sockfd, &msg, 0);
	if (bytes_sent < 0) {
		log_error("Sendmsg failed");
		return 1;
	}

	close(sockfd);

	return 0;
}
