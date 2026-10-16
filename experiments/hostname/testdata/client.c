// Controlled, nonblocking TLS client for the experiment. stdin gates every
// operation so the test can attach before any socket is created.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct connection { SSL *ssl; int fd; int used; } connections[128];
static SSL_CTX *ctx;
static int family, port;
static const char *address;
static uintptr_t last_freed_ssl;
static unsigned int reused_objects;

static void die(const char *what) { perror(what); exit(1); }
static void check(int ok, const char *what) { if (!ok) die(what); }
static int connect_socket(void)
{
	int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	check(fd >= 0, "socket");
	if (family == AF_INET) {
		struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
		check(inet_pton(family, address, &a.sin_addr) == 1, "address");
		check(connect(fd, (void *)&a, sizeof(a)) == 0, "connect");
	} else {
		struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
		check(inet_pton(family, address, &a.sin6_addr) == 1, "address");
		check(connect(fd, (void *)&a, sizeof(a)) == 0, "connect");
	}
	check(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "nonblocking");
	return fd;
}
static void report(int i)
{
	uint64_t cookie = 0;
	socklen_t len = sizeof(cookie);
	// The test independently checks the BPF program generated this cookie
	// already; SO_COOKIE could itself generate one if the hook failed.
	check(getsockopt(connections[i].fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) == 0, "SO_COOKIE");
	printf("socket %d %" PRIu64 " %d\n", i, cookie, connections[i].fd);
}
static SSL *new_ssl(int fd, const char *name, const char *order, const char *mode)
{
	SSL *ssl = SSL_new(ctx);
	check(ssl != NULL, "SSL_new");
	if ((uintptr_t)ssl == last_freed_ssl) reused_objects++;
	SSL_set_connect_state(ssl);
	if (!strcmp(order, "name-first") && strcmp(name, "-"))
		check(SSL_set_tlsext_host_name(ssl, name) == 1, "hostname");
	if (!strcmp(mode, "memory")) {
		BIO *r = BIO_new(BIO_s_mem()), *w = BIO_new(BIO_s_mem());
		check(r && w, "BIO_new");
		SSL_set_bio(ssl, r, w);
	} else {
		check(SSL_set_fd(ssl, fd) == 1, "SSL_set_fd");
	}
	if (strcmp(order, "name-first") && strcmp(name, "-"))
		check(SSL_set_tlsext_host_name(ssl, name) == 1, "hostname");
	return ssl;
}
static void *handshake(void *arg)
{
	int i = *(int *)arg;
	int ret = SSL_connect(connections[i].ssl);
	printf("handshake %d %d %d\n", i, ret, SSL_get_error(connections[i].ssl, ret));
	return NULL;
}
// An application BIO callback may cancel a write before it reaches the
// socket, leaving the raw socket BIO and descriptor relationship intact.
static long reject_write(BIO *bio, int oper, const char *argp, size_t len,
                         int argi, long argl, int ret, size_t *processed)
{
	(void)bio; (void)argp; (void)len; (void)argi; (void)argl; (void)processed;
	if (oper == BIO_CB_WRITE) return 0;
	return ret;
}
int main(int argc, char **argv)
{
	check(argc == 4, "arguments: client 4|6 destination port");
	family = !strcmp(argv[1], "4") ? AF_INET : AF_INET6;
	address = argv[2]; port = atoi(argv[3]);
	ctx = SSL_CTX_new(TLS_client_method());
	check(ctx != NULL, "SSL_CTX_new");
	setvbuf(stdout, NULL, _IOLBF, 0);
	puts("ready");
	char line[1024], op[32], name[512], order[32], mode[32];
	while (fgets(line, sizeof(line), stdin)) {
		int i = -1;
		check(sscanf(line, "%31s", op) == 1, "command");
		if (!strcmp(op, "stats")) {
			printf("stats %u\n", reused_objects);
			continue;
		}
		if (!strcmp(op, "open")) {
			check(sscanf(line, "%*s %511s %31s %31s", name, order, mode) == 3, "open");
			for (i = 0; i < 128 && connections[i].used; i++);
			check(i < 128, "slots");
			int fd = connect_socket();
			if (!strcmp(mode, "dup")) {
				int copy = fcntl(fd, F_DUPFD_CLOEXEC, 256);
				check(copy >= 0, "dup"); close(fd); fd = copy;
			}
			connections[i] = (struct connection){.ssl = new_ssl(fd, name, order, mode), .fd = fd, .used = 1};
			report(i);
			continue;
		}
		check(sscanf(line, "%*s %d", &i) == 1 && i >= 0 && i < 128 && connections[i].used, "slot");
		struct connection *c = &connections[i];
		if (!strcmp(op, "handshake")) {
			handshake(&i);
		} else if (!strcmp(op, "thread")) {
			pthread_t t;
			check(pthread_create(&t, NULL, handshake, &i) == 0, "pthread_create");
			check(pthread_join(t, NULL) == 0, "pthread_join");
		} else if (!strcmp(op, "fail")) {
			BIO_set_callback_ex(SSL_get_wbio(c->ssl), reject_write);
			handshake(&i);
		} else if (!strcmp(op, "replace")) {
			check(sscanf(line, "%*s %*d %511s", name) == 1, "replace");
			last_freed_ssl = (uintptr_t)c->ssl;
			SSL_free(c->ssl);
			c->ssl = new_ssl(c->fd, name, "fd-first", "fd");
			puts("ok");
		} else if (!strcmp(op, "rebind")) {
			int fd = connect_socket();
			check(SSL_set_fd(c->ssl, fd) == 1, "rebind");
			close(c->fd); c->fd = fd;
			report(i);
		} else if (!strcmp(op, "badfd")) {
			int fd = c->fd;
			close(fd);
			int other = open("/dev/null", O_RDWR | O_CLOEXEC);
			check(other == fd, "descriptor reuse");
			puts("ok");
		} else if (!strcmp(op, "close")) {
			last_freed_ssl = (uintptr_t)c->ssl;
			SSL_free(c->ssl); close(c->fd); c->used = 0;
			puts("ok");
		} else { die("unknown command"); }
	}
	for (int i = 0; i < 128; i++) {
		if (connections[i].used) { SSL_free(connections[i].ssl); close(connections[i].fd); }
	}
	SSL_CTX_free(ctx);
	return 0;
}
