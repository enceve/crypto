// Use of this source code is governed by a license
// that can be found in the LICENSE file.
// +build amd64,!appengine,!gccgo

package siphash

//go:noescape
func blocks(h *siphash, p []uint8)

//go:noescape
func finalize(h *siphash) uint64

//go:noescape
func flush(h *siphash)
