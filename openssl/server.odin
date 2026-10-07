package openssl

import "core:strings"

// Server-side TLS for the HTTP server, used non-blocking over memory BIOs like the clients.

/*
A server context with the certificate chain (PEM, leaf first) and private key (PEM) from the given
files: TLS 1.2 at least, for TLS 1.2 only ECDHE key exchange with AEAD ciphers (Mozilla's
"intermediate" profile, no CBC) in the server's order of preference, no renegotiation, no
compression, ALPN "http/1.1", and buffers released while a connection is idle.

Returns nil and the reason when the files can't be used.
*/
server_ctx :: proc(cert_file, key_file: string) -> (ctx: ^SSL_CTX, why: string) {
	ERR_clear_error()
	ctx = SSL_CTX_new(TLS_server_method())
	if ctx == nil { return nil, error_string() }

	ok := SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1 && SSL_CTX_set_cipher_list(ctx, TLS12_CIPHERS) == 1
	SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_SERVER_PREFERENCE)
	SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_RELEASE_BUFFERS, nil)
	SSL_CTX_set_alpn_select_cb(ctx, select_http11, nil)
	if !ok {
		SSL_CTX_free(ctx)
		return nil, error_string()
	}

	if SSL_CTX_use_certificate_chain_file(ctx, strings.clone_to_cstring(cert_file, context.temp_allocator)) != 1 {
		why = strings.concatenate({"certificate ", cert_file, ": ", error_string()}, context.temp_allocator)
		SSL_CTX_free(ctx)
		return nil, why
	}
	if SSL_CTX_use_PrivateKey_file(ctx, strings.clone_to_cstring(key_file, context.temp_allocator), SSL_FILETYPE_PEM) != 1 {
		why = strings.concatenate({"private key ", key_file, ": ", error_string()}, context.temp_allocator)
		SSL_CTX_free(ctx)
		return nil, why
	}
	if SSL_CTX_check_private_key(ctx) != 1 {
		why = strings.concatenate({"private key doesn't match the certificate: ", error_string()}, context.temp_allocator)
		SSL_CTX_free(ctx)
		return nil, why
	}
	return ctx, ""
}

// A server connection over memory BIOs (owned by `ssl`), see `client_ssl`.
server_ssl :: proc(ctx: ^SSL_CTX) -> (ssl: ^SSL, rbio, wbio: ^BIO, ok: bool) {
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
	SSL_set_accept_state(ssl)
	return ssl, rbio, wbio, true
}

// TLS 1.2 cipher suites (TLS 1.3 has its own, all AEAD): forward secrecy and AEAD only.
@(private)
TLS12_CIPHERS :: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"

@(private)
HTTP11_ALPN := [?]u8{8, 'h', 't', 't', 'p', '/', '1', '.', '1'}

// Picks "http/1.1" when the client offers it; otherwise the handshake continues without ALPN
// (a client that only offers h2 then finds out it got HTTP/1.1, which is what it would get anyway).
@(private)
select_http11 :: proc "c" (ssl: ^SSL, out: ^[^]u8, outlen: ^u8, input: [^]u8, inlen: u32, arg: rawptr) -> i32 {
	if SSL_select_next_proto(out, outlen, raw_data(HTTP11_ALPN[:]), len(HTTP11_ALPN), input, inlen) == OPENSSL_NPN_NEGOTIATED {
		return SSL_TLSEXT_ERR_OK
	}
	return SSL_TLSEXT_ERR_NOACK
}
