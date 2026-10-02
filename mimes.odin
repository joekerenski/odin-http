package http

import "core:path/filepath"

Mime_Type :: enum {
	Plain,
	Octet_Stream,

	Avif,
	Css,
	Csv,
	Gif,
	Html,
	Ico,
	Jpeg,
	Js,
	Json,
	Markdown,
	Mp3,
	Mp4,
	Ogg,
	Otf,
	Pdf,
	Png,
	Svg,
	Ttf,
	Url_Encoded,
	Wasm,
	Wav,
	Webm,
	Webp,
	Woff,
	Woff2,
	Xml,
	Zip,
}

// Determines the type from the file extension (case-insensitive). Unknown extensions are
// `.Octet_Stream`, so browsers download instead of guessing (and possibly rendering) them.
mime_from_extension :: proc(s: string) -> Mime_Type {
	ext_buf: [8]byte
	ext := filepath.ext(s)
	if len(ext) > len(ext_buf) { return .Octet_Stream }
	for i in 0 ..< len(ext) {
		c := ext[i]
		ext_buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	ext = string(ext_buf[:len(ext)])

	//odinfmt:disable
	switch ext {
	case ".html", ".htm": return .Html
	case ".js", ".mjs":   return .Js
	case ".css":          return .Css
	case ".csv":          return .Csv
	case ".xml":          return .Xml
	case ".zip":          return .Zip
	case ".json", ".map": return .Json
	case ".ico":          return .Ico
	case ".gif":          return .Gif
	case ".jpeg", ".jpg": return .Jpeg
	case ".png":          return .Png
	case ".svg":          return .Svg
	case ".wasm":         return .Wasm
	case ".txt", ".text": return .Plain
	case ".md":           return .Markdown
	case ".avif":         return .Avif
	case ".webp":         return .Webp
	case ".pdf":          return .Pdf
	case ".mp3":          return .Mp3
	case ".mp4":          return .Mp4
	case ".webm":         return .Webm
	case ".ogg", ".oga":  return .Ogg
	case ".wav":          return .Wav
	case ".woff":         return .Woff
	case ".woff2":        return .Woff2
	case ".ttf":          return .Ttf
	case ".otf":          return .Otf
	case:                 return .Octet_Stream
	}
	//odinfmt:enable
}

@(private="file")
_mime_to_content_type := [Mime_Type]string{
	.Plain        = "text/plain; charset=utf-8",
	.Octet_Stream = "application/octet-stream",

	.Avif         = "image/avif",
	.Css          = "text/css; charset=utf-8",
	.Csv          = "text/csv; charset=utf-8",
	.Gif          = "image/gif",
	.Html         = "text/html; charset=utf-8",
	.Ico          = "image/vnd.microsoft.icon",
	.Jpeg         = "image/jpeg",
	.Js           = "text/javascript; charset=utf-8",
	.Json         = "application/json",
	.Markdown     = "text/markdown; charset=utf-8",
	.Mp3          = "audio/mpeg",
	.Mp4          = "video/mp4",
	.Ogg          = "audio/ogg",
	.Otf          = "font/otf",
	.Pdf          = "application/pdf",
	.Png          = "image/png",
	.Svg          = "image/svg+xml",
	.Ttf          = "font/ttf",
	.Url_Encoded  = "application/x-www-form-urlencoded",
	.Wasm         = "application/wasm",
	.Wav          = "audio/wav",
	.Webm         = "video/webm",
	.Webp         = "image/webp",
	.Woff         = "font/woff",
	.Woff2        = "font/woff2",
	.Xml          = "text/xml; charset=utf-8",
	.Zip          = "application/zip",
}

mime_to_content_type :: proc(m: Mime_Type) -> string {
	return _mime_to_content_type[m]
}
