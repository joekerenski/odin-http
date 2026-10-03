package openssl

import "core:strings"
import "core:sync"

// Client-side TLS shared by the HTTP client and the WebSocket client: always verifying, used
// non-blocking over memory BIOs (the callers move the ciphertext with nbio).

@(private)
default_client_ctx: ^SSL_CTX
@(private)
default_client_ctx_once: sync.Once

/*
A client context that verifies the server: its certificate chain against the system's trust store,
or the CA certificates in `ca_file` (PEM) when given. TLS 1.2 at least. The host name is checked per
connection, see `client_ssl`.

Returns a reference the caller releases with `SSL_CTX_free`, nil when the context can't be set up
(the reason is in `error_string`).
*/
client_ctx :: proc(ca_file := "") -> ^SSL_CTX {
	make_ctx :: proc(ca_file: string) -> ^SSL_CTX {
		ctx := SSL_CTX_new(TLS_client_method())
		if ctx == nil { return nil }
		ok: i32
		if ca_file == "" {
			ok = SSL_CTX_set_default_verify_paths(ctx)
		} else {
			ok = SSL_CTX_load_verify_locations(ctx, strings.clone_to_cstring(ca_file, context.temp_allocator), nil)
		}
		if ok != 1 || SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 {
			SSL_CTX_free(ctx)
			return nil
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
		return ctx
	}

	if ca_file != "" { return make_ctx(ca_file) }

	// The system trust store is loaded once and shared.
	sync.once_do(&default_client_ctx_once, proc() { default_client_ctx = make_ctx("") })
	if default_client_ctx == nil { return nil }
	SSL_CTX_up_ref(default_client_ctx)
	return default_client_ctx
}

/*
A client connection to `host` (a name, or an IP address without brackets) over memory BIOs:
ciphertext from the server goes into `rbio`, ciphertext for the server comes out of `wbio`. Both
are owned by `ssl` (freed by `SSL_free`).

Names are sent as SNI and must match the certificate; addresses get no SNI (RFC 6066 3) and must
be in the certificate's IP SANs.
*/
client_ssl :: proc(ctx: ^SSL_CTX, host: string, is_ip: bool) -> (ssl: ^SSL, rbio, wbio: ^BIO, ok: bool) {
	ssl = SSL_new(ctx)
	if ssl == nil { return }
	rbio = BIO_new(BIO_s_mem())
	wbio = BIO_new(BIO_s_mem())
	if rbio == nil || wbio == nil {
		if rbio != nil { BIO_free(rbio) }
		if wbio != nil { BIO_free(wbio) }
		SSL_free(ssl)
		return nil, nil, nil, false
	}
	SSL_set_bio(ssl, rbio, wbio)
	SSL_set_connect_state(ssl)

	chost := strings.clone_to_cstring(host, context.temp_allocator)
	if is_ip {
		ok = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), chost) == 1
	} else {
		ok = SSL_set_tlsext_host_name(ssl, chost) == 1 && SSL_set1_host(ssl, chost) == 1
	}
	if !ok {
		SSL_free(ssl)
		return nil, nil, nil, false
	}
	return
}

// Why the certificate was rejected, "" when verification didn't fail.
verify_error :: proc(ssl: ^SSL) -> string {
	v := SSL_get_verify_result(ssl)
	if v == X509_V_OK { return "" }
	return string(X509_verify_cert_error_string(v))
}

// OpenSSL's queued errors as text (clears the queue).
error_string :: proc(allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	for {
		e := ERR_get_error()
		if e == 0 { break }
		buf: [256]byte
		ERR_error_string_n(e, raw_data(buf[:]), len(buf))
		if strings.builder_len(sb) > 0 { strings.write_string(&sb, "; ") }
		strings.write_string(&sb, string(cstring(raw_data(buf[:]))))
	}
	if strings.builder_len(sb) == 0 { return "unknown error" }
	return strings.to_string(sb)
}

// Moves the ciphertext waiting in `wbio` to the end of `out`, returns how much.
drain_bio :: proc(wbio: ^BIO, out: ^[dynamic]byte) -> int {
	total := 0
	for {
		pending := int(BIO_ctrl_pending(wbio))
		if pending <= 0 { return total }
		at := len(out)
		non_zero_resize(out, at + pending)
		n := int(BIO_read(wbio, raw_data(out[at:]), i32(pending)))
		non_zero_resize(out, at + max(n, 0))
		if n <= 0 { return total }
		total += n
	}
}
