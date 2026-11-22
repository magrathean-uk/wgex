// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	testZone   = "test.wgex."
	leakZone   = "leak.wgex.test."
	markerTag  = "WGEXLEAK "
	maxNonce   = 128
	dnsMaxSize = 512
)

// validNonce accepts the characters leakprobe uses; anything else is not
// recorded as a marker (it is still answered or logged as a plain request).
func validNonce(s string) bool {
	if s == "" || len(s) > maxNonce {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// udpMarkerNonce extracts the nonce from a datagram of the form
// "WGEXLEAK <nonce>[ anything]".
func udpMarkerNonce(p []byte) (string, bool) {
	i := bytes.Index(p, []byte(markerTag))
	if i < 0 {
		return "", false
	}
	rest := p[i+len(markerTag):]
	if j := bytes.IndexAny(rest, " \t\r\n\x00"); j >= 0 {
		rest = rest[:j]
	}
	n := string(rest)
	return n, validNonce(n)
}

// leakNonce returns the nonce for "<nonce>.leak.wgex.test." names.
func leakNonce(name string) (string, bool) {
	if !strings.HasSuffix(name, "."+leakZone) {
		return "", false
	}
	n := strings.TrimSuffix(name, "."+leakZone)
	return n, validNonce(n)
}

func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// dnsAnswerer answers a single-question DNS query. answer4/answer6 are the
// addresses returned for matching names (invalid means no record of that
// type). testZoneOn enables *.test.wgex.
type dnsAnswerer struct {
	answer4, answer6 netip.Addr
	testZoneOn       bool
}

type dnsResult struct {
	name, qtype, rcode string
	nonce              string
	marker             bool
}

func (a dnsAnswerer) handle(req []byte) ([]byte, dnsResult, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil || h.Response {
		return nil, dnsResult{}, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, dnsResult{}, false
	}
	name := strings.ToLower(q.Name.String())
	res := dnsResult{name: name, qtype: strings.TrimPrefix(q.Type.String(), "Type")}

	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RCode: dnsmessage.RCodeNameError}
	var answers []dnsmessage.Resource
	matched := false
	if n, ok := leakNonce(name); ok {
		matched, res.nonce, res.marker = true, n, true
	} else if inZone(name, leakZone) {
		matched = true
	} else if a.testZoneOn && inZone(name, testZone) {
		matched = true
	}
	if matched {
		rh.RCode = dnsmessage.RCodeSuccess
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}
		switch q.Type {
		case dnsmessage.TypeA:
			if a.answer4.IsValid() {
				hdr.Type = dnsmessage.TypeA
				answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a.answer4.As4()}})
			}
		case dnsmessage.TypeAAAA:
			if a.answer6.IsValid() {
				hdr.Type = dnsmessage.TypeAAAA
				answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a.answer6.As16()}})
			}
		}
	}
	res.rcode = strings.TrimPrefix(rh.RCode.String(), "RCode")

	b := dnsmessage.NewBuilder(make([]byte, 0, dnsMaxSize), rh)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, res, false
	}
	if err := b.Question(q); err != nil {
		return nil, res, false
	}
	if err := b.StartAnswers(); err != nil {
		return nil, res, false
	}
	for _, r := range answers {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(r.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(r.Header, *body)
		}
		if err != nil {
			return nil, res, false
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, res, false
	}
	return out, res, true
}
