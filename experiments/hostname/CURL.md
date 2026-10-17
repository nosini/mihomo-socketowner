# Verified curl custom-BIO send path

The optional observer library profile
`openssl-3.5.3-curl-8.22.0-x86-64-v3` adds one verified libcurl transport path to
the existing OpenSSL socket-BIO path. Select it explicitly and supply `-libcurl`
to `run` or `prepare`, alongside the existing library/target/reader flags.
The original `openssl-3.5.3-x86-64-v3` profile continues to leave curl unattributed.

Use the exact regular file that the target mapped, not a SONAME symlink. In
addition to the three hashes in [OBSERVER.md](OBSERVER.md), this profile requires:

| Library | SHA256 |
| --- | --- |
| libcurl 8.22.0 (`libcurl.so.4.8.0`) | `7f8ac4aad1fbe3d994a849004df8169479717de45a7af78b72448318bb395ff6` |

For example, change the observer command's `-profile` value to the curl profile
and add `-libcurl /usr/lib64/libcurl.so.4.8.0` before `run` or `prepare`.
Both preparation and attachment hash the file and match its device/inode and
mapping base in the selected target. A missing libcurl, wrong hash, symlink or
unmapped identical copy is rejected before a registration is published.
A library update requires re-verifying the adapter; a version string is insufficient.

## Live association

[Curl's OpenSSL backend](https://github.com/curl/curl/blob/curl-8_22_0/lib/vtls/openssl.c)
uses a custom BIO whose data points to its SSL connection filter. The verified
path is SSL → HAPPY-EYEBALLS → TCP, on socket index zero. The middle filter's
send callback tail-calls TCP and contributes no stack frame. Other filter chains
are unknown; there is no generic memory-BIO admission or cached setter lookup.

At `lsm/socket_sendmsg`, the adapter requires the exact libc `sendto(2)` syscall
path with `MSG_NOSIGNAL`, no destination address, and these live frames:

| Frame | Return PC relative to library | Stack advance |
| --- | ---: | ---: |
| libc syscall cancellation | libc `0x9abb1` | 32 bytes, or verified 56-byte cancellable path |
| libc send wrapper | libc `0x12a54b` | 32 bytes |
| curl TCP send | libcurl `0x2bfe7` | 32 bytes |
| curl BIO callback caller | libcurl `0xc216c` | 336 bytes; saved BIO at SP + 288 |
| OpenSSL legacy BIO adapter | libcrypto `0x17aeeb` | 80 bytes |

It then follows the same fixed OpenSSL BIO/record frames as [SEND.md](SEND.md)
and [RETRIES.md](RETRIES.md), recovering the current SSL object from its live
caller. No stack scanning is used. Disassembly and live syscall stops verified
both TLS 1.2 and 1.3 with the actual mapped binaries.

The SSL object's initialized buffering BIO must point to this custom BIO. Its
method type is `BIO_TYPE_MEM`, but its write callback must be exactly the verified
curl callback at `0xc20f0`. The BIO's data must point to the verified SSL filter,
whose backend points back to the same SSL and BIO method. Its next filter must
be the exact HAPPY-EYEBALLS type, then the exact TCP type in the live syscall's
saved register. All three filters must share one connection owner and index zero;
TCP has no next filter, and its socket context's descriptor equals the syscall FD.

The kernel hook supplies the actual held socket, independently of descriptor
slot reuse. The existing first-send guard, TCP sequence checks, immutable complete
ClientHello window, packet comparison, remaining-byte retry checks and retirement
leases are unchanged. Unsupported later sends revoke discovery evidence without
moving an already committed route. The reader still uses v1/profile 3, and the
process-owner ABI remains unchanged. No extra attachment or permission is needed.
Small BPF subprograms keep the combined verifier stack within 512 bytes; no new
scratch map or cached object state is introduced.

## Validation and limits

The service harness's `--curl-adapter` group starts unmodified curl with its
libraries loaded, registers that exact TGID/cgroup, activates the confined observer,
and only then supplies its transfer configuration. Private CA trust and SPKI pins
remain enabled. Both TLS versions and both IP families pass through confined
system-stack TUN and local nftables auto-redirect:

- `route.invalid` selects NAMED and `reuse.invalid` selects RENAMED, preserving
  the real destination. The API retains empty real-IP host metadata; its Domain
  rule and payload establish which name was used for matching.
- Wrong-host and wrong-SPKI-pin checks deliver no HTTP request (curl exit 60/90).
- Stopping the observer before transfer preserves verified HTTPS through DIRECT.
- The original profile, tested with `--curl-compat`, remains unattributed.

Per mode/family, the new profile adds twelve TLS connections: eight successful
HTTPS requests and four intentional verification rejections. Two successes use
a test-only constructor that creates and joins a thread before curl reads config,
forcing libc's cancellable syscall path without interposing TLS/socket calls.
The remaining cases use the installed binary without that constructor. Live
syscall stops independently confirm both libc paths for both TLS versions. A BPF TestRun checks a
valid object chain and rejects malformed callbacks, filters, owners, SSL/method
back-references, unreadable pointers, nonzero indexes and descriptor mismatches.
Preparation tests reject unsupported library choices before publishing a target.
The earlier supported-path lifetime, retry, guard, observer and routing regressions
remain required after BPF changes.

This verifies this build's direct TCP HTTP/1.1 curl requests. Curl HTTP/2,
coalescing, automatic retries, proxy TLS layers, custom socket callbacks, other
builds/architectures, early data and ECH remain unproved. The controlled HTTP/2
and 421 tests use their separate fixture; they do not establish curl behavior.
No browser/NSS or production performance claim follows from these tests.
