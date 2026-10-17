// Deterministic API-contract regression for the controlled fixture's shutdown.
// Build with --wrap=SSL_shutdown, --wrap=SSL_get_error, --wrap=poll and
// --wrap=shutdown; see TLS.md. The real TLS/network matrix remains separate.
#define main hostname_fixture_main
#include "client.c"
#undef main
#include <assert.h>

static int steps[4], calls, polls, closed, wants_io;

int __wrap_SSL_shutdown(SSL *ssl)
{
	assert(ssl == (SSL *)&connections[0]);
	assert(calls < 4);
	return steps[calls++];
}

int __wrap_SSL_get_error(const SSL *ssl, int ret)
{
	assert(ssl == (SSL *)&connections[0]);
	assert(ret == -1); // zero must be retried, never treated as a failure
	return calls == 1 ? SSL_ERROR_WANT_WRITE : SSL_ERROR_WANT_READ;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	assert(wants_io && count == 1 && fds[0].fd == 7 && timeout > 0);
	assert(fds[0].events == (polls == 0 ? POLLOUT : POLLIN));
	polls++;
	return 1;
}

int __wrap_shutdown(int fd, int how)
{
	assert(fd == 7 && how == SHUT_WR);
	closed++;
	return 0;
}

int main(void)
{
	connections[0].ssl = (SSL *)&connections[0];
	connections[0].fd = 7;
	// The peer's close_notify is buffered: no kernel poll is needed between
	// the initial progress return and completion. The old loop polls here.
	steps[0] = 0; steps[1] = 1;
	shutdown_tls(0);
	assert(calls == 2 && polls == 0 && closed == 1);
	// An actual I/O failure must poll the direction OpenSSL requests. A zero
	// between WANT_WRITE and WANT_READ must still progress without polling.
	calls = polls = closed = 0;
	wants_io = 1;
	steps[0] = -1; steps[1] = 0; steps[2] = -1; steps[3] = 1;
	shutdown_tls(0);
	assert(calls == 4 && polls == 2 && closed == 1);
	puts("PASS shutdown progress and nonblocking I/O directions");
	return 0;
}
