package himalaya

import (
	"encoding/json"
	"fmt"
	"time"
)

// BodyKind says which variant a message body came from.
type BodyKind int

// Body variants of a read message.
const (
	BodyNone BodyKind = iota
	BodyText
	BodyHTML
)

// Message is the part of a message read result the wrapper uses: the
// top-level headers and one body. HTML is returned raw; callers strip it.
type Message struct {
	MessageID string
	Date      string // RFC 3339, empty when absent
	Subject   string
	From      []Address
	To        []Address
	Cc        []Address
	ReplyTo   []Address
	Body      string
	BodyKind  BodyKind
}

// The mail-parser JSON (cli section 7). Bodies other than Text and Html
// (Binary, InlineBinary, Message, Multipart) are never decoded.
type rawMessage struct {
	HTMLBody []int     `json:"html_body"`
	TextBody []int     `json:"text_body"`
	Parts    []rawPart `json:"parts"`
}

type rawPart struct {
	Headers []rawHeader `json:"headers"`
	Body    struct {
		Text *string `json:"Text"`
		HTML *string `json:"Html"`
	} `json:"body"`
}

// rawHeader.Name is a snake_case string for the headers mail-parser knows and
// {"other": name} for the rest (X-*, Precedence, ...), which fails to decode
// as a string and is skipped.
type rawHeader struct {
	Name  json.RawMessage `json:"name"`
	Value json.RawMessage `json:"value"`
}

// rawHeaderValue covers the variants the wrapper reads. Others, including
// the unit variant "Empty", fail to decode and are skipped.
type rawHeaderValue struct {
	Text     *string `json:"Text"`
	DateTime *struct {
		Year        int  `json:"year"`
		Month       int  `json:"month"`
		Day         int  `json:"day"`
		Hour        int  `json:"hour"`
		Minute      int  `json:"minute"`
		Second      int  `json:"second"`
		TZBeforeGMT bool `json:"tz_before_gmt"`
		TZHour      int  `json:"tz_hour"`
		TZMinute    int  `json:"tz_minute"`
	} `json:"DateTime"`
	Address *struct {
		List  []rawParsedAddress `json:"List"`
		Group []struct {
			Addresses []rawParsedAddress `json:"addresses"`
		} `json:"Group"`
	} `json:"Address"`
}

type rawParsedAddress struct {
	Name    *string `json:"name"`
	Address *string `json:"address"`
}

// ParseMessage decodes message read output. The body is the first text_body
// part with a Text body; failing that, the first Html part of html_body or text_body.
func ParseMessage(out []byte) (Message, error) {
	raw, err := decode[rawMessage](out)
	if err != nil {
		return Message{}, err
	}
	if len(raw.Parts) == 0 {
		return Message{}, fmt.Errorf("message has no parts")
	}
	var m Message
	for _, h := range raw.Parts[0].Headers {
		var name string
		var v rawHeaderValue
		if json.Unmarshal(h.Name, &name) != nil || json.Unmarshal(h.Value, &v) != nil {
			continue
		}
		switch name {
		case "message_id":
			m.MessageID = deref(v.Text)
		case "subject":
			m.Subject = deref(v.Text)
		case "date":
			if d := v.DateTime; d != nil {
				off := (d.TZHour*60 + d.TZMinute) * 60
				if d.TZBeforeGMT {
					off = -off
				}
				t := time.Date(d.Year, time.Month(d.Month), d.Day, d.Hour, d.Minute, d.Second, 0, time.FixedZone("", off))
				m.Date = t.Format(time.RFC3339)
			}
		case "from", "to", "cc", "reply_to":
			if v.Address == nil {
				continue
			}
			addrs := parsedAddresses(v.Address.List)
			for _, g := range v.Address.Group {
				addrs = append(addrs, parsedAddresses(g.Addresses)...)
			}
			switch name {
			case "from":
				m.From = addrs
			case "to":
				m.To = addrs
			case "cc":
				m.Cc = addrs
			case "reply_to":
				m.ReplyTo = addrs
			}
		}
	}

	part := func(i int) *rawPart {
		if i < 0 || i >= len(raw.Parts) {
			return nil
		}
		return &raw.Parts[i]
	}
	for _, i := range raw.TextBody {
		if p := part(i); p != nil && p.Body.Text != nil {
			m.Body, m.BodyKind = *p.Body.Text, BodyText
			return m, nil
		}
	}
	for _, i := range append(raw.HTMLBody, raw.TextBody...) {
		if p := part(i); p != nil && p.Body.HTML != nil {
			m.Body, m.BodyKind = *p.Body.HTML, BodyHTML
			return m, nil
		}
	}
	return m, nil
}

func parsedAddresses(raw []rawParsedAddress) []Address {
	out := make([]Address, 0, len(raw))
	for _, r := range raw {
		out = append(out, Address{Name: deref(r.Name), Email: deref(r.Address)})
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
