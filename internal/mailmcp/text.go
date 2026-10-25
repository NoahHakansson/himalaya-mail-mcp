package mailmcp

import (
	"html"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
)

// maxHeaderBytes caps every header-like string taken from mail.
const maxHeaderBytes = 1000

// dropped reports characters removed from mail text: those of
// config.IsUnsafeRune, which the mailbox rule also refuses, except \n and \t.
func dropped(r rune) bool {
	return r != '\n' && r != '\t' && config.IsUnsafeRune(r)
}

// sanitize cleans untrusted mail text: invalid UTF-8 becomes U+FFFD, CRLF
// becomes LF, and the characters in dropped are removed.
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "\ufffd")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		if dropped(r) {
			return -1
		}
		return r
	}, s)
}

// sanitizeLine is sanitize for header fields: newlines and tabs become
// spaces, and the result is capped at maxHeaderBytes.
func sanitizeLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, sanitize(s))
	t, _ := truncate(s, maxHeaderBytes)
	return t
}

// truncate cuts s to at most n bytes at a UTF-8 boundary and reports whether it cut.
func truncate(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// Tags whose content is dropped entirely, and tags that end a line.
var (
	hiddenTags = map[string]bool{"script": true, "style": true, "head": true}
	blockTags  = map[string]bool{
		"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "dd": true,
		"div": true, "dl": true, "dt": true, "footer": true, "h1": true, "h2": true, "h3": true,
		"h4": true, "h5": true, "h6": true, "header": true, "hr": true, "li": true, "ol": true,
		"p": true, "pre": true, "section": true, "table": true, "td": true, "th": true, "tr": true, "ul": true,
	}
	blankLines = regexp.MustCompile(`\n{3,}`)
	lineSpace  = regexp.MustCompile(`[ \t]+\n`)
)

// stripHTML turns HTML into plain text with the standard library only. It
// drops script, style, head and comments, turns block tags and <br> into
// newlines, removes every other tag with its attributes (so src and href
// disappear), unescapes entities and collapses blank lines.
func stripHTML(s string) string {
	var b strings.Builder
	hidden := "" // the tag whose content is being skipped
	for len(s) > 0 {
		lt := strings.IndexByte(s, '<')
		if lt < 0 {
			if hidden == "" {
				b.WriteString(s)
			}
			break
		}
		if hidden == "" {
			b.WriteString(s[:lt])
		}
		s = s[lt:]
		if !startsTag(s) {
			if hidden == "" {
				b.WriteByte('<')
			}
			s = s[1:]
			continue
		}
		if strings.HasPrefix(s, "<!--") {
			end := strings.Index(s[4:], "-->")
			if end < 0 {
				break
			}
			s = s[4+end+3:]
			continue
		}
		end := tagEnd(s)
		if end < 0 {
			break // an unterminated tag hides the rest
		}
		name, closing := tagName(s[1:end])
		s = s[end+1:]
		switch {
		case hidden != "":
			if closing && name == hidden {
				hidden = ""
			}
		case hiddenTags[name] && !closing:
			hidden = name
		case blockTags[name]:
			b.WriteByte('\n')
		}
	}
	text := html.UnescapeString(b.String())
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = lineSpace.ReplaceAllString(text, "\n")
	text = blankLines.ReplaceAllString(text, "\n\n")
	return strings.TrimSpace(text)
}

// startsTag reports whether the '<' at s[0] opens markup rather than being a literal.
func startsTag(s string) bool {
	if len(s) < 2 {
		return false
	}
	c := s[1]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '/' || c == '!' || c == '?'
}

// tagEnd finds the '>' that closes the tag starting at s[0], skipping quoted attribute values.
func tagEnd(s string) int {
	var quote byte
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
	}
	return -1
}

// tagName returns the lowercased element name of a tag body such as "/p" or "img src=x".
func tagName(body string) (string, bool) {
	closing := strings.HasPrefix(body, "/")
	body = strings.TrimPrefix(body, "/")
	end := strings.IndexFunc(body, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	})
	if end >= 0 {
		body = body[:end]
	}
	return strings.ToLower(body), closing
}
