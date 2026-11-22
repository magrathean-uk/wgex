// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type httpHandler = http.Handler

const (
	maxBigBytes = 2 << 30 // 2 GiB
	maxDelayMS  = 120_000
)

func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
}

func remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *Server) tunnelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "wgex testpeer: /ip /echo /big?bytes=N /delay?ms=N /leak/<nonce>")
	})
	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, remoteIP(r).String())
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		// Full duplex lets a streaming upload be echoed while it arrives.
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n < 0 || n > maxBigBytes {
			http.Error(w, "bytes must be 0..2147483648", http.StatusBadRequest)
			return
		}
		var seed [32]byte
		_, _ = rand.Read(seed[:])
		src := mrand.NewChaCha8(seed)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		_, _ = io.CopyN(w, src, n)
	})
	mux.HandleFunc("/delay", func(w http.ResponseWriter, r *http.Request) {
		ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
		if err != nil || ms < 0 || ms > maxDelayMS {
			http.Error(w, "ms must be 0..120000", http.StatusBadRequest)
			return
		}
		t := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer t.Stop()
		select {
		case <-t.C:
			fmt.Fprintln(w, "ok")
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/leak/", func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimPrefix(r.URL.Path, "/leak/")
		if !validNonce(nonce) {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		s.marker("in_tunnel", "http", nonce, remoteIP(r), r.Host)
		fmt.Fprintln(w, "ok")
	})
	return mux
}

func (s *Server) markerHandler(listener string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/leak/", func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimPrefix(r.URL.Path, "/leak/")
		if !validNonce(nonce) {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		s.marker("outside_tunnel", "http", nonce, remoteIP(r), listener)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.ev.Debug("marker_listener_other", "path", r.URL.Path, "src", remoteIP(r).String())
		http.NotFound(w, r)
	})
	return mux
}
