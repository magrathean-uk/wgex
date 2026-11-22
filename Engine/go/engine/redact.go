// SPDX-License-Identifier: MIT

package engine

// redactKeys replaces key-shaped runs, including keys glued to surrounding
// letters. Ordinary words are unchanged. wireguard-go never logs keys; this
// guards against a future upstream change.
func redactKeys(b []byte) []byte {
	isHex := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
	isB64 := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
	}
	var out []byte
	last := 0
	mask := func(start, end int) {
		out = append(append(out, b[last:start]...), "(redacted)"...)
		last = end
	}
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && isB64(b[j]) {
			j++
		}
		if j == i {
			i++
			continue
		}
		if j-i >= 43 && j < len(b) && b[j] == '=' {
			mask(i, j+1)
			i = j + 1
			continue
		}
		// A hex key may begin inside a longer alphanumeric run. Inspect each
		// hex subrun without rescanning the rest of the word (linear time).
		for k := i; k < j; {
			end := k
			for end < j && isHex(b[end]) {
				end++
			}
			if end-k >= 64 {
				mask(k, end)
			}
			if end == k {
				k++
			} else {
				k = end
			}
		}
		i = j
	}
	if out == nil {
		return b
	}
	return append(out, b[last:]...)
}
