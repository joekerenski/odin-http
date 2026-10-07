#!/usr/bin/env bash
# Test-only certificates for tests/server/tls_test.odin (never use them for anything else): two
# independent CAs (ca_a.pem, ca_b.pem; their keys are discarded) and a server certificate from
# each for localhost, 127.0.0.1 and ::1, valid for 100 years. Needs OpenSSL 3.
set -euo pipefail
cd "$(dirname "$0")"
O=${OPENSSL:-openssl}
for n in a b; do
	$O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca_$n.key -out ca_$n.pem -days 36500 -subj "/CN=odin-http test CA $n"
	$O req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server_$n.key -out server_$n.csr -subj "/CN=localhost"
	printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" > ext.cnf
	$O x509 -req -in server_$n.csr -CA ca_$n.pem -CAkey ca_$n.key -CAcreateserial -out server_$n.pem -days 36500 -extfile ext.cnf
	rm -f server_$n.csr ext.cnf ca_$n.srl ca_$n.key
done
