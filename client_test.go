package cloudflare

import (
	"fmt"
	"strings"
	"testing"
)

// dkimSample is a 410-byte DKIM-shaped string, mirroring the reproduction in
// https://github.com/libdns/cloudflare/issues/32.
var dkimSample = "v=DKIM1; k=rsa; p=" + strings.Repeat("ABCDEFGH", 49)

func TestUnwrapContent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "unquoted_legacy", in: "hello", want: "hello"},
		{name: "single_segment", in: `"foo"`, want: "foo"},
		{name: "empty_segment", in: `""`, want: ""},
		{name: "two_segments", in: `"a" "b"`, want: "ab"},
		{name: "no_separator", in: `"a""b"`, want: "ab"},
		{name: "tab_separator", in: "\"a\"\t\"b\"", want: "ab"},
		{name: "multiple_space_separator", in: `"a"  "b"`, want: "ab"},
		{name: "escaped_quote", in: `"a\"b"`, want: `a"b`},
		{name: "escaped_backslash", in: `"a\\b"`, want: `a\b`},
		{
			name: "dkim_two_chunks",
			in:   fmt.Sprintf("%q %q", dkimSample[:255], dkimSample[255:]),
			want: dkimSample,
		},
		// Malformed inputs return as-is rather than panic.
		{name: "unterminated_quote", in: `"abc`, want: `"abc`},
		{name: "trailing_garbage", in: `"a" junk`, want: `"a" junk`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unwrapContent(tc.in)
			if got != tc.want {
				t.Errorf("unwrapContent(%q) = %q (len %d), want %q (len %d)",
					tc.in, got, len(got), tc.want, len(tc.want))
			}
		})
	}
}

func TestWrapContent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: `""`},
		{name: "short", in: "hello", want: `"hello"`},
		{name: "with_quote_and_backslash", in: `a"b\c`, want: `"a\"b\\c"`},
		{
			name: "exactly_255_bytes",
			in:   strings.Repeat("a", 255),
			want: fmt.Sprintf("%q", strings.Repeat("a", 255)),
		},
		{
			name: "256_bytes",
			in:   strings.Repeat("a", 256),
			want: fmt.Sprintf("%q %q", strings.Repeat("a", 255), "a"),
		},
		{
			name: "510_bytes",
			in:   strings.Repeat("a", 510),
			want: fmt.Sprintf("%q %q", strings.Repeat("a", 255), strings.Repeat("a", 255)),
		},
		{
			name: "dkim_410_bytes",
			in:   dkimSample,
			want: fmt.Sprintf("%q %q", dkimSample[:255], dkimSample[255:]),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wrapContent(tc.in)
			if got != tc.want {
				t.Errorf("wrapContent(%q) = %q (len %d), want %q (len %d)",
					tc.in, got, len(got), tc.want, len(tc.want))
			}
		})
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	// 'é' = 0xC3 0xA9. With 254 'a' bytes before it, byte 254 is 0xC3 (end of chunk 1)
	// and byte 255 is 0xA9 (start of chunk 2). Verifies that splitting a UTF-8 rune
	// at a chunk boundary still round-trips byte-identical.
	straddle := strings.Repeat("a", 254) + "é" + "trail"

	inputs := map[string]string{
		"empty":                 "",
		"short_ascii":           "hello",
		"hello_world":           "Hello, world!",
		"spf":                   "v=spf1 -all",
		"exactly_255":           strings.Repeat("a", 255),
		"256_bytes":             strings.Repeat("a", 256),
		"510_bytes":             strings.Repeat("a", 510),
		"dkim_410":              dkimSample,
		"embedded_quote_bslash": `embedded "quote" and \ backslash`,
		"raw_bytes":             "\xff\x00\x01 raw bytes",
		"utf8_rune_straddle":    straddle,
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			wrapped := wrapContent(in)
			got := unwrapContent(wrapped)
			if got != in {
				t.Errorf("round-trip failed:\n  input   (len %d) = %q\n  wrapped (len %d) = %q\n  got     (len %d) = %q",
					len(in), in, len(wrapped), wrapped, len(got), got)
			}
		})
	}
}
