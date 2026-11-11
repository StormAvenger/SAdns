package dnsclient

import (
	"errors"
	"testing"

	"github.com/StormAvenger/SAdns/internal/dnswire"
)

func reply(q *dnswire.Msg) *dnswire.Msg {
	return &dnswire.Msg{Header: dnswire.Header{ID: q.ID, QR: true, RD: true, RA: true}, Question: q.Question,
		Answer: []dnswire.RR{{Name: q.Question[0].Name, Type: dnswire.TypeA, Class: 1, TTL: 60, Data: []byte{1, 2, 3, 4}}}}
}

func TestValidate(t *testing.T) {
	q := dnswire.NewQuery("example.com", dnswire.TypeA, dnswire.QueryOpts{})
	if err := Validate(q, reply(q), nil, false); err != nil {
		t.Fatalf("good reply rejected: %v", err)
	}
	cases := map[string]func(m *dnswire.Msg){
		"missing QR": func(m *dnswire.Msg) { m.QR = false },
		"wrong ID":   func(m *dnswire.Msg) { m.ID++ },
		"wrong name": func(m *dnswire.Msg) {
			m.Question = []dnswire.Question{{Name: "evil.com.", Type: dnswire.TypeA, Class: 1}}
		},
		"wrong type": func(m *dnswire.Msg) {
			m.Question = []dnswire.Question{{Name: "example.com.", Type: dnswire.TypeAAAA, Class: 1}}
		},
		"answer, no qdata": func(m *dnswire.Msg) { m.Question = nil },
	}
	for name, mut := range cases {
		m := reply(q)
		mut(m)
		if err := Validate(q, m, nil, false); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: want mismatch, got %v", name, err)
		}
	}
	if err := Validate(q, reply(q), dnswire.ErrShort, false); err == nil {
		t.Error("parse error accepted")
	}
	tr := reply(q)
	tr.TC = true
	if err := Validate(q, tr, dnswire.ErrShort, true); err != nil {
		t.Errorf("truncated UDP rejected: %v", err)
	}
	if err := Validate(q, nil, dnswire.ErrShort, true); err == nil {
		t.Error("nil message accepted")
	}
	// Errors without a question section are acceptable (no answer to attribute).
	e := reply(q)
	e.Question, e.Answer, e.Rcode = nil, nil, dnswire.RcodeFormErr
	if err := Validate(q, e, nil, false); err != nil {
		t.Errorf("FORMERR without question rejected: %v", err)
	}
}
