package github

import "bytes"

func newBytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
