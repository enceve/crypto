// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64, !appengine, !gccgo

package siphash

//go:noescape
func core(hVal *[4]uint64, msg []byte)

//go:noescape
func finalize(hVal *[4]uint64, block *[TagSize]byte) uint64
