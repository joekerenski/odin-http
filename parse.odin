package http

// Strict, allocation-free parsers and validators for the HTTP/1.1 grammar (RFC 9110, RFC 9112).
//
// Everything that decides message framing goes through here, so the rules are in one place and
// can be tested (and fuzzed) without a socket. None of these procedures panic on any input.

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
@(private)
TCHAR := #partial [256]bool {
	'!' = true, '#' = true, '$' = true, '%' = true, '&' = true, '\'' = true, '*' = true,
	'+' = true, '-' = true, '.' = true, '^' = true, '_' = true, '`' = true, '|' = true, '~' = true,
	'0' = true, '1' = true, '2' = true, '3' = true, '4' = true, '5' = true, '6' = true, '7' = true, '8' = true, '9' = true,
	'a' = true, 'b' = true, 'c' = true, 'd' = true, 'e' = true, 'f' = true, 'g' = true, 'h' = true, 'i' = true,
	'j' = true, 'k' = true, 'l' = true, 'm' = true, 'n' = true, 'o' = true, 'p' = true, 'q' = true, 'r' = true,
	's' = true, 't' = true, 'u' = true, 'v' = true, 'w' = true, 'x' = true, 'y' = true, 'z' = true,
	'A' = true, 'B' = true, 'C' = true, 'D' = true, 'E' = true, 'F' = true, 'G' = true, 'H' = true, 'I' = true,
	'J' = true, 'K' = true, 'L' = true, 'M' = true, 'N' = true, 'O' = true, 'P' = true, 'Q' = true, 'R' = true,
	'S' = true, 'T' = true, 'U' = true, 'V' = true, 'W' = true, 'X' = true, 'Y' = true, 'Z' = true,
}

is_tchar :: #force_inline proc "contextless" (c: byte) -> bool {
	return TCHAR[c]
}

// token = 1*tchar
is_token :: proc "contextless" (s: string) -> bool {
	if len(s) == 0 { return false }
	for i in 0 ..< len(s) {
		if !TCHAR[s[i]] { return false }
	}
	return true
}

// field-value = *field-content; we accept VCHAR, obs-text (0x80-0xFF), SP and HTAB.
// CR, LF, NUL, DEL and the other CTLs are rejected.
is_field_value :: proc "contextless" (s: string) -> bool {
	for i in 0 ..< len(s) {
		c := s[i]
		if (c < 0x20 && c != '\t') || c == 0x7f { return false }
	}
	return true
}

// OWS = *( SP / HTAB )
trim_ows :: proc "contextless" (s: string) -> string {
	s := s
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') { s = s[1:] }
	for len(s) > 0 && (s[len(s) - 1] == ' ' || s[len(s) - 1] == '\t') { s = s[:len(s) - 1] }
	return s
}

// ASCII case-insensitive equality.
ascii_equal_fold :: proc "contextless" (a, b: string) -> bool {
	if len(a) != len(b) { return false }
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' { x += 32 }
		if y >= 'A' && y <= 'Z' { y += 32 }
		if x != y { return false }
	}
	return true
}

// Content-Length = 1*DIGIT, without sign, separators or overflow.
//
// RFC 9110 8.6 allows a recipient to accept a list of identical values ("5, 5") as one value,
// which is what a proxy produces when it merges duplicate fields. We accept that and nothing else.
parse_content_length :: proc "contextless" (s: string) -> (n: int, ok: bool) {
	s := s
	first := -1
	for {
		comma := -1
		for i in 0 ..< len(s) {
			if s[i] == ',' { comma = i; break }
		}
		elem := trim_ows(s if comma < 0 else s[:comma])

		v := parse_decimal(elem) or_return
		if first >= 0 && v != first { return 0, false }
		first = v

		if comma < 0 { break }
		s = s[comma + 1:]
	}
	return first, true
}

// 1*DIGIT into a non-negative int; false on empty, non-digit or overflow.
parse_decimal :: proc "contextless" (s: string) -> (n: int, ok: bool) {
	if len(s) == 0 { return 0, false }
	for i in 0 ..< len(s) {
		c := s[i]
		if c < '0' || c > '9' { return 0, false }
		d := int(c - '0')
		if n > (max(int) - d) / 10 { return 0, false }
		n = n * 10 + d
	}
	return n, true
}

// chunk-size = 1*HEXDIG, followed by optional chunk extensions (`*( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`).
//
// Extensions are validated for illegal bytes but otherwise ignored.
parse_chunk_size_line :: proc "contextless" (line: string) -> (size: int, ok: bool) {
	i := 0
	hex_digit :: proc "contextless" (c: byte) -> (int, bool) {
		switch c {
		case '0' ..= '9': return int(c - '0'), true
		case 'a' ..= 'f': return int(c - 'a' + 10), true
		case 'A' ..= 'F': return int(c - 'A' + 10), true
		}
		return 0, false
	}

	for i < len(line) {
		d := hex_digit(line[i]) or_break
		if size > (max(int) - d) / 16 { return 0, false }
		size = size * 16 + d
		i += 1
	}
	if i == 0 { return 0, false }

	rest := trim_ows(line[i:])
	if len(rest) == 0 { return size, true }
	if rest[0] != ';' { return 0, false }
	// The extensions themselves: only reject bytes that can never appear (CTLs other than HTAB).
	if !is_field_value(rest) { return 0, false }
	return size, true
}

Transfer_Encoding_Result :: enum {
	// Final coding is chunked, and it is the only coding: we can decode this.
	Chunked,
	// Syntactically invalid, or chunked is not the final coding / appears more than once: 400.
	Invalid,
	// Valid list, but contains a coding we don't implement (gzip, ...): 501.
	Unsupported,
}

// Parses a Transfer-Encoding field value (a comma separated, case-insensitive list of codings,
// possibly with parameters). We only implement "chunked", so anything else is unsupported.
parse_transfer_encoding :: proc "contextless" (value: string) -> Transfer_Encoding_Result {
	s := value
	codings, chunked_at := 0, -1
	unsupported := false
	for {
		comma := -1
		for i in 0 ..< len(s) {
			if s[i] == ',' { comma = i; break }
		}
		elem := trim_ows(s if comma < 0 else s[:comma])

		// Empty list elements are allowed by the list syntax (RFC 9110 5.6.1) and ignored.
		if len(elem) > 0 {
			name := elem
			for i in 0 ..< len(elem) {
				if elem[i] == ';' || elem[i] == ' ' || elem[i] == '\t' { name = elem[:i]; break }
			}
			if !is_token(name) || !is_field_value(elem) { return .Invalid }

			if ascii_equal_fold(name, "chunked") {
				// chunked takes no parameters, and must only be applied once.
				if len(name) != len(elem) || chunked_at >= 0 { return .Invalid }
				chunked_at = codings
			} else {
				unsupported = true
			}
			codings += 1
		}

		if comma < 0 { break }
		s = s[comma + 1:]
	}

	if codings == 0 { return .Invalid }
	// RFC 9112 6.3: if chunked is not the final coding in a request, the length can't be determined.
	if chunked_at != codings - 1 { return .Invalid }
	if unsupported { return .Unsupported }
	return .Chunked
}

// Reports whether the comma separated, case-insensitive token list `value` contains `token`.
// Used for Connection, Upgrade and similar list fields.
header_list_has_token :: proc "contextless" (value: string, token: string) -> bool {
	s := value
	for {
		comma := -1
		for i in 0 ..< len(s) {
			if s[i] == ',' { comma = i; break }
		}
		if ascii_equal_fold(trim_ows(s if comma < 0 else s[:comma]), token) { return true }
		if comma < 0 { return false }
		s = s[comma + 1:]
	}
}

// HTTP-version = "HTTP/" DIGIT "." DIGIT (RFC 9112 2.3), case-sensitive.
parse_http_version :: proc "contextless" (s: string) -> (v: Version, ok: bool) {
	if len(s) != 8 || s[:5] != "HTTP/" || s[6] != '.' { return }
	if s[5] < '0' || s[5] > '9' || s[7] < '0' || s[7] > '9' { return }
	return Version{s[5] - '0', s[7] - '0'}, true
}

// request-target as received on the wire: non-empty, no CTLs, SP or DEL.
// Bytes >= 0x80 are rejected too, a compliant client percent-encodes them.
is_request_target :: proc "contextless" (s: string) -> bool {
	if len(s) == 0 { return false }
	for i in 0 ..< len(s) {
		c := s[i]
		if c <= 0x20 || c >= 0x7f { return false }
	}
	return true
}

Range_Result :: enum {
	// No usable Range: serve the whole representation with 200.
	None,
	// A single satisfiable range: serve it with 206.
	Partial,
	// Valid syntax, but no range overlaps the representation: 416.
	Unsatisfiable,
}

// Parses a Range header value (RFC 9110 14.2) for a representation of `size` bytes.
//
// Only a single "bytes" range is supported; anything else (other units, multiple ranges, invalid
// syntax) yields `.None` so the full representation is served, which the RFC permits.
parse_range :: proc "contextless" (value: string, size: int) -> (start, length: int, result: Range_Result) {
	PREFIX :: "bytes="
	v := trim_ows(value)
	if len(v) <= len(PREFIX) || !ascii_equal_fold(v[:len(PREFIX)], PREFIX) { return }
	spec := trim_ows(v[len(PREFIX):])

	for i in 0 ..< len(spec) {
		if spec[i] == ',' { return } // Multiple ranges.
	}

	dash := -1
	for i in 0 ..< len(spec) {
		if spec[i] == '-' { dash = i; break }
	}
	if dash < 0 { return }

	first_str, last_str := spec[:dash], spec[dash + 1:]
	switch {
	case first_str == "":
		// Suffix range: the last N bytes.
		n, ok := parse_decimal(last_str)
		if !ok { return }
		if n == 0 { return 0, 0, .Unsatisfiable }
		if size == 0 { return 0, 0, .Unsatisfiable }
		n = min(n, size)
		return size - n, n, .Partial

	case:
		first, ok := parse_decimal(first_str)
		if !ok { return }
		last := size - 1
		if last_str != "" {
			last, ok = parse_decimal(last_str)
			if !ok { return 0, 0, .None }
			if last < first { return 0, 0, .None }
			last = min(last, size - 1)
		}
		if first >= size { return 0, 0, .Unsatisfiable }
		return first, last - first + 1, .Partial
	}
}
