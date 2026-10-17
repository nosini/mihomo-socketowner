// Controlled, nonblocking TLS client for the experiment. stdin gates every
// operation so the test can attach before any socket is created.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct connection { SSL *ssl; int fd; int used; char pin[65]; } connections[512];
static SSL_CTX *ctx;
static int family, port;
static const char *address;
static int source_port, tiny_send, any_source;
static char destination[64];
static uintptr_t last_freed_ssl;
static unsigned int reused_objects;

static void die(const char *what) { perror(what); exit(1); }
static void check(int ok, const char *what) { if (!ok) die(what); }
static int connect_socket(void)
{
	int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	check(fd >= 0, "socket");
	if (tiny_send) {
		int size = 1024, mss = 512;
		check(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0, "send buffer");
		check(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) == 0, "TCP MSS");
	}
	int one = 1;
	check(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0, "reuse address");
	{ // Keep the source address identical when forcing redirect collisions.
		// A routed (TUN) destination needs the source its route selects.
		if (family == AF_INET) {
			struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(source_port),
				.sin_addr.s_addr = htonl(any_source ? INADDR_ANY : INADDR_LOOPBACK)};
			check(bind(fd, (void *)&local, sizeof(local)) == 0, "bind source");
		} else {
			struct sockaddr_in6 local = {.sin6_family = AF_INET6, .sin6_port = htons(source_port),
				.sin6_addr = any_source ? in6addr_any : in6addr_loopback};
			check(bind(fd, (void *)&local, sizeof(local)) == 0, "bind source");
		}
	}
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
	struct sockaddr_storage local;
	len = sizeof(local);
	check(getsockname(connections[i].fd, (void *)&local, &len) == 0, "getsockname");
	unsigned short local_port = family == AF_INET ? ((struct sockaddr_in *)&local)->sin_port : ((struct sockaddr_in6 *)&local)->sin6_port;
	printf("socket %d %" PRIu64 " %d %u\n", i, cookie, connections[i].fd, ntohs(local_port));
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
// Only the full-TLS fixture uses these bounded retries. The old commands keep
// their single-call behavior for send-order and attribution regression tests.
static int64_t monotonic_ms(void)
{
	struct timespec now;
	check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock");
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int retry_tls(struct connection *c, int error, int64_t deadline)
{
	if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return 0;
	for (;;) {
		int64_t remaining = deadline - monotonic_ms();
		if (remaining <= 0) return 0;
		struct pollfd fd = {.fd = c->fd, .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT};
		int ret = poll(&fd, 1, (int)remaining);
		if (ret < 0 && errno == EINTR) continue;
		return ret > 0;
	}
}
static void exchange(int i)
{
	struct connection *c = &connections[i];
	int64_t deadline = monotonic_ms() + 5000;
	int ret, error;
	do {
		ERR_clear_error();
		ret = SSL_connect(c->ssl);
		error = SSL_get_error(c->ssl, ret);
	} while (ret != 1 && retry_tls(c, error, deadline));
	if (ret != 1) {
		printf("exchange %d handshake-failed %ld\n", i, SSL_get_verify_result(c->ssl));
		return;
	}
	// Check the exact peer certificate before sending application data. The
	// private test CA is loaded only into this client, never the system store.
	X509 *peer = SSL_get1_peer_certificate(c->ssl);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int length = 0;
	check(peer && X509_digest(peer, EVP_sha256(), digest, &length) == 1 && length == 32, "peer digest");
	X509_free(peer);
	char pin[65];
	for (unsigned int n = 0; n < length; n++) snprintf(pin + n * 2, 3, "%02x", digest[n]);
	if (strcmp(c->pin, pin)) {
		printf("exchange %d pin-failed\n", i);
		return;
	}
	static const char request[] = "hostname-fixture-request\n";
	static const char response[] = "hostname-fixture-response\n";
	size_t written = 0;
	do {
		ERR_clear_error();
		ret = SSL_write_ex(c->ssl, request, sizeof(request) - 1, &written);
		error = SSL_get_error(c->ssl, ret);
	} while (ret != 1 && retry_tls(c, error, deadline));
	check(ret == 1 && written == sizeof(request) - 1, "TLS request");
	char received[sizeof(response) - 1];
	size_t offset = 0;
	while (offset < sizeof(received)) {
		size_t count = 0;
		ERR_clear_error();
		ret = SSL_read_ex(c->ssl, received + offset, sizeof(received) - offset, &count);
		error = SSL_get_error(c->ssl, ret);
		if (ret != 1) {
			check(retry_tls(c, error, deadline), "TLS response");
			continue;
		}
		offset += count;
	}
	check(!memcmp(received, response, sizeof(received)), "TLS response bytes");
	printf("exchange %d ok %s\n", i, SSL_get_version(c->ssl));
}
struct parallel_send { int slot, error; pthread_barrier_t *barrier; };
static void *parallel_handshake(void *arg)
{
	struct parallel_send *send = arg;
	int ret = pthread_barrier_wait(send->barrier);
	check(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD, "barrier wait");
	ret = SSL_connect(connections[send->slot].ssl);
	send->error = SSL_get_error(connections[send->slot].ssl, ret);
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
// Deliberately corrupt a pending BIO buffer in a negative retry test.
static long mutate_write(BIO *bio, int oper, const char *argp, size_t len,
                         int argi, long argl, int ret, size_t *processed)
{
	(void)bio; (void)argi; (void)argl; (void)processed;
	if (oper == BIO_CB_WRITE && len) ((unsigned char *)argp)[0] ^= 1;
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
		if (!strcmp(op, "tiny-send") || !strcmp(op, "normal-send")) {
			tiny_send = !strcmp(op, "tiny-send");
			puts("ok"); continue;
		}
		if (!strcmp(op, "any-source")) {
			any_source = 1;
			puts("ok"); continue;
		}
		if (!strcmp(op, "source")) {
			check(sscanf(line, "%*s %d", &source_port) == 1, "source port");
			puts("ok"); continue;
		}
		if (!strcmp(op, "destination")) {
			check(sscanf(line, "%*s %63s %d", destination, &port) == 2, "destination");
			address = destination;
			puts("ok"); continue;
		}
		if (!strcmp(op, "stats")) {
			printf("stats %u\n", reused_objects);
			continue;
		}
		if (!strcmp(op, "open")) {
			check(sscanf(line, "%*s %511s %31s %31s", name, order, mode) == 3, "open");
			for (i = 0; i < 512 && connections[i].used; i++);
			check(i < 512, "slots");
			int fd = connect_socket();
			if (!strcmp(mode, "dup")) {
				int copy = fcntl(fd, F_DUPFD_CLOEXEC, 256);
				check(copy >= 0, "dup"); close(fd); fd = copy;
			}
			connections[i] = (struct connection){.ssl = new_ssl(fd, name, order, mode), .fd = fd, .used = 1};
			report(i);
			continue;
		}
		check(sscanf(line, "%*s %d", &i) == 1 && i >= 0 && i < 512 && connections[i].used, "slot");
		struct connection *c = &connections[i];
		if (!strcmp(op, "verify")) {
			char ca[512], hostname[256], pin[65];
			int version;
			check(sscanf(line, "%*s %*d %511s %255s %64s %d", ca, hostname, pin, &version) == 4, "verify");
			check(strlen(pin) == 64 && (version == 12 || version == 13), "verify arguments");
			X509_STORE *store = X509_STORE_new();
			check(store && X509_STORE_load_locations(store, ca, NULL) == 1, "test CA");
			check(SSL_set1_verify_cert_store(c->ssl, store) == 1, "connection trust store");
			X509_STORE_free(store);
			SSL_set_verify(c->ssl, SSL_VERIFY_PEER, NULL);
			check(SSL_set1_host(c->ssl, hostname) == 1, "verified hostname");
			int protocol = version == 12 ? TLS1_2_VERSION : TLS1_3_VERSION;
			check(SSL_set_min_proto_version(c->ssl, protocol) == 1 &&
			      SSL_set_max_proto_version(c->ssl, protocol) == 1, "TLS version");
			memcpy(c->pin, pin, sizeof(pin));
			puts("ok");
		} else if (!strcmp(op, "exchange")) {
			exchange(i);
		} else if (!strcmp(op, "handshake")) {
			handshake(&i);
		} else if (!strcmp(op, "cork-one") || !strcmp(op, "ack")) {
			int one = 1;
			if (!strcmp(op, "cork-one")) {
				check(setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &one, sizeof(one)) == 0, "cork");
				int ret = SSL_connect(c->ssl);
				check(SSL_get_error(c->ssl, ret) == SSL_ERROR_WANT_READ, "corked handshake");
			} else {
				char byte;
				check(read(c->fd, &byte, 1) == 1 && byte == 'P', "read probe");
				check(setsockopt(c->fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one)) == 0, "quick ack");
			}
			int queued = 0;
			check(ioctl(c->fd, SIOCOUTQNSD, &queued) == 0 && queued > 0, "unsent corked bytes");
			printf("corked %d\n", queued);
		} else if (!strcmp(op, "cork-pair") || !strcmp(op, "parallel")) {
			int j;
			check(sscanf(line, "%*s %*d %d", &j) == 1 && j >= 0 && j < 512 && j != i && connections[j].used, "second slot");
			int one = 1;
			check(setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &one, sizeof(one)) == 0, "cork");
			if (!strcmp(op, "parallel")) {
				pthread_barrier_t barrier;
				pthread_t threads[2];
				check(pthread_barrier_init(&barrier, NULL, 2) == 0, "barrier init");
				struct parallel_send sends[2] = {{i, 0, &barrier}, {j, 0, &barrier}};
				for (int n = 0; n < 2; n++)
					check(pthread_create(&threads[n], NULL, parallel_handshake, &sends[n]) == 0, "parallel create");
				for (int n = 0; n < 2; n++) {
					check(pthread_join(threads[n], NULL) == 0, "parallel join");
					check(sends[n].error == SSL_ERROR_WANT_READ, "parallel handshake");
				}
				check(pthread_barrier_destroy(&barrier) == 0, "barrier destroy");
			} else {
				int ret = SSL_connect(c->ssl);
				check(SSL_get_error(c->ssl, ret) == SSL_ERROR_WANT_READ, "first corked handshake");
				ret = SSL_connect(connections[j].ssl);
				check(SSL_get_error(connections[j].ssl, ret) == SSL_ERROR_WANT_READ, "second corked handshake");
			}
			int queued = 0;
			check(ioctl(c->fd, SIOCOUTQNSD, &queued) == 0 && queued > 0, "unsent corked bytes");
			printf("corked %d\n", queued);
		} else if (!strcmp(op, "uncork")) {
			int zero = 0;
			check(setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &zero, sizeof(zero)) == 0, "uncork");
			puts("ok");
		} else if (!strcmp(op, "thread")) {
			pthread_t t;
			check(pthread_create(&t, NULL, handshake, &i) == 0, "pthread_create");
			check(pthread_join(t, NULL) == 0, "pthread_join");
		} else if (!strcmp(op, "implicit")) {
			size_t written = 0;
			int ret = SSL_write_ex(c->ssl, "x", 1, &written);
			printf("implicit %d %d %d\n", i, ret, SSL_get_error(c->ssl, ret));
		} else if (!strcmp(op, "large-alpn") || !strcmp(op, "retry-alpn") || !strcmp(op, "oversize-alpn")) {
			unsigned char protocols[16384];
			int count = !strcmp(op, "large-alpn") ? 16 : !strcmp(op, "retry-alpn") ? 40 : 64;
			for (int n = 0; n < count; n++) {
				protocols[n * 256] = 255;
				memset(&protocols[n * 256 + 1], 'a' + n % 26, 255);
			}
			check(SSL_set_alpn_protos(c->ssl, protocols, count * 256) == 0, "large ALPN");
			puts("ok");
		} else if (!strcmp(op, "alias")) {
			check(sscanf(line, "%*s %*d %511s", name) == 1, "alias");
			int j;
			for (j = 0; j < 512 && connections[j].used; j++);
			check(j < 512, "alias slots");
			int fd = fcntl(c->fd, F_DUPFD_CLOEXEC, 256);
			check(fd >= 0, "alias dup");
			connections[j] = (struct connection){.ssl = new_ssl(fd, name, "fd-first", "fd"), .fd = fd, .used = 1};
			report(j);
		} else if (!strcmp(op, "raw") || !strcmp(op, "raw-child")) {
			if (!strcmp(op, "raw-child")) {
				pid_t child = fork();
				check(child >= 0, "fork");
				if (!child) _exit(write(c->fd, "x", 1) == 1 ? 0 : 1);
				int status;
				check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child write");
			} else {
				check(write(c->fd, "x", 1) == 1, "raw write");
			}
			puts("ok");
		} else if (!strcmp(op, "rename")) {
			check(sscanf(line, "%*s %*d %511s", name) == 1, "rename");
			check(SSL_set_tlsext_host_name(c->ssl, name) == 1, "rename hostname");
			puts("ok");
		} else if (!strcmp(op, "mutate-write")) {
			BIO_set_callback_ex(SSL_get_wbio(c->ssl), mutate_write);
			puts("ok");
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
	for (int i = 0; i < 512; i++) {
		if (connections[i].used) { SSL_free(connections[i].ssl); close(connections[i].fd); }
	}
	SSL_CTX_free(ctx);
	return 0;
}
