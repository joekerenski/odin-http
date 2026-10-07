package openssl

import "core:c"
import "core:c/libc"

// Links the system OpenSSL (3.x). macOS and Linux only.
when ODIN_OS == .Darwin {
	foreign import lib {
		"system:ssl.3",
		"system:crypto.3",
	}
} else {
	foreign import lib {
		"system:ssl",
		"system:crypto",
	}
}

Version :: bit_field u32 {
	pre_release: uint | 4,
	patch:       uint | 16,
	minor:       uint | 8,
	major:       uint | 4,
}

VERSION: Version

@(private, init)
version_check :: proc "contextless" () {
	VERSION = Version(OpenSSL_version_num())
	assert_contextless(VERSION.major == 3, "invalid OpenSSL library version, expected 3.x")
}

SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}
BIO :: struct {}
BIO_METHOD :: struct {}
X509_VERIFY_PARAM :: struct {}

SSL_CTRL_SET_TLSEXT_HOSTNAME   :: 55
SSL_CTRL_SET_MIN_PROTO_VERSION :: 123

TLSEXT_NAMETYPE_host_name :: 0

TLS1_2_VERSION :: 0x0303

SSL_VERIFY_PEER :: 0x01

X509_V_OK :: 0

SSL_ERROR_NONE        :: 0
SSL_ERROR_SSL         :: 1
SSL_ERROR_WANT_READ   :: 2
SSL_ERROR_WANT_WRITE  :: 3
SSL_ERROR_SYSCALL     :: 5
SSL_ERROR_ZERO_RETURN :: 6

SSL_FILETYPE_PEM :: 1

SSL_OP_NO_COMPRESSION   :: u64(1) << 17
SSL_OP_SERVER_PREFERENCE :: u64(1) << 22
SSL_OP_NO_RENEGOTIATION :: u64(1) << 30

SSL_CTRL_MODE            :: 33
SSL_MODE_RELEASE_BUFFERS :: 0x10

SSL_TLSEXT_ERR_OK    :: 0
SSL_TLSEXT_ERR_NOACK :: 3

OPENSSL_NPN_NEGOTIATED :: 1

ALPN_Select_Proc :: #type proc "c" (ssl: ^SSL, out: ^[^]u8, outlen: ^u8, input: [^]u8, inlen: c.uint, arg: rawptr) -> c.int

foreign lib {
	TLS_client_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_write :: proc(ssl: ^SSL, buf: [^]byte, num: c.int) -> c.int ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_CTX_up_ref :: proc(ctx: ^SSL_CTX) -> c.int ---
	ERR_print_errors_fp :: proc(fp: ^libc.FILE) ---
	SSL_ctrl :: proc(ssl: ^SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	OpenSSL_version_num :: proc() -> c.ulong ---

	// Verification.
	SSL_CTX_ctrl :: proc(ctx: ^SSL_CTX, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_CTX_set_verify :: proc(ctx: ^SSL_CTX, mode: c.int, callback: rawptr) ---
	SSL_CTX_set_default_verify_paths :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_load_verify_locations :: proc(ctx: ^SSL_CTX, ca_file: cstring, ca_path: cstring) -> c.int ---
	SSL_set1_host :: proc(ssl: ^SSL, hostname: cstring) -> c.int ---
	SSL_get_verify_result :: proc(ssl: ^SSL) -> c.long ---
	SSL_get0_param :: proc(ssl: ^SSL) -> ^X509_VERIFY_PARAM ---
	X509_VERIFY_PARAM_set1_ip_asc :: proc(param: ^X509_VERIFY_PARAM, ipasc: cstring) -> c.int ---
	X509_verify_cert_error_string :: proc(n: c.long) -> cstring ---

	// Non-blocking use over memory BIOs.
	BIO_s_mem :: proc() -> ^BIO_METHOD ---
	BIO_new :: proc(method: ^BIO_METHOD) -> ^BIO ---
	BIO_free :: proc(b: ^BIO) -> c.int ---
	BIO_read :: proc(b: ^BIO, data: [^]byte, dlen: c.int) -> c.int ---
	BIO_write :: proc(b: ^BIO, data: [^]byte, dlen: c.int) -> c.int ---
	BIO_ctrl_pending :: proc(b: ^BIO) -> c.size_t ---
	SSL_set_bio :: proc(ssl: ^SSL, rbio, wbio: ^BIO) ---
	SSL_set_connect_state :: proc(ssl: ^SSL) ---
	SSL_do_handshake :: proc(ssl: ^SSL) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_pending :: proc(ssl: ^SSL) -> c.int ---

	// Server side.
	TLS_server_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_set_options :: proc(ctx: ^SSL_CTX, op: u64) -> u64 ---
	SSL_CTX_set_cipher_list :: proc(ctx: ^SSL_CTX, list: cstring) -> c.int ---
	SSL_CTX_use_certificate_chain_file :: proc(ctx: ^SSL_CTX, file: cstring) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_set_alpn_select_cb :: proc(ctx: ^SSL_CTX, cb: ALPN_Select_Proc, arg: rawptr) ---
	SSL_select_next_proto :: proc(out: ^[^]u8, outlen: ^u8, server: [^]u8, server_len: c.uint, client: [^]u8, client_len: c.uint) -> c.int ---
	SSL_get0_alpn_selected :: proc(ssl: ^SSL, data: ^[^]u8, len: ^c.uint) ---
	SSL_set_accept_state :: proc(ssl: ^SSL) ---

	ERR_get_error :: proc() -> c.ulong ---
	ERR_clear_error :: proc() ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]byte, len: c.size_t) ---
}

// This is a macro in c land.
SSL_CTX_set_min_proto_version :: proc(ctx: ^SSL_CTX, version: c.long) -> c.int {
	return c.int(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil))
}

// This is a macro in c land.
SSL_set_tlsext_host_name :: proc(ssl: ^SSL, name: cstring) -> c.int {
	return c.int(SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)))
}

ERR_print_errors :: proc {
	ERR_print_errors_fp,
	ERR_print_errors_stderr,
}

ERR_print_errors_stderr :: proc() {
	ERR_print_errors_fp(libc.stderr)
}
