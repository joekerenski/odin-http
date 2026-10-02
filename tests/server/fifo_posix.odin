#+build !windows
package tests_server

import "core:strings"
import "core:sys/posix"

make_fifo :: proc(path: string) {
	posix.mkfifo(strings.clone_to_cstring(path, context.temp_allocator), {.IRUSR, .IWUSR})
}
