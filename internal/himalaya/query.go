package himalaya

import (
	"errors"
	"strings"
	"time"
)

// Search holds validated search criteria. Empty strings and nil pointers are unset.
type Search struct {
	From, To, Subject, Body string
	Since, Before, On       *time.Time
	Unseen, Flagged         *bool
}

const dateLayout = "2006-01-02"

// Query renders the criteria in Himalaya's search grammar (cli section 5):
// quoted patterns with \ and " escaped, since/before/on mapped onto after and
// date, clauses joined with "and", and a trailing "order by date desc" so a
// pattern containing "order by" never splits the query. Dates match the
// Date: header, not INTERNALDATE.
func (s Search) Query() (string, error) {
	var clauses []string
	for _, p := range []struct{ field, value string }{
		{"from", s.From}, {"to", s.To}, {"subject", s.Subject}, {"body", s.Body},
	} {
		if p.value != "" {
			clauses = append(clauses, p.field+" "+quote(p.value))
		}
	}
	dayBefore := func(t *time.Time) string { return t.AddDate(0, 0, -1).Format(dateLayout) }
	if s.Since != nil {
		clauses = append(clauses, "after "+dayBefore(s.Since))
	}
	if s.Before != nil {
		clauses = append(clauses, "not after "+dayBefore(s.Before))
	}
	if s.On != nil {
		clauses = append(clauses, "date "+s.On.Format(dateLayout))
	}
	if s.Unseen != nil {
		clauses = append(clauses, map[bool]string{true: "not flag seen", false: "flag seen"}[*s.Unseen])
	}
	if s.Flagged != nil {
		clauses = append(clauses, map[bool]string{true: "flag flagged", false: "not flag flagged"}[*s.Flagged])
	}
	if len(clauses) == 0 {
		return "", errors.New("at least one search criterion is required")
	}
	return strings.Join(clauses, " and ") + " order by date desc", nil
}

func quote(p string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
}
