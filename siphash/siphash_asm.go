// Use of this source code is governed by a license
// that can be found in the LICENSE file.
// +build amd64,!appengine,!gccgo

package siphash

// updates the hash value by processing the p slice
//go:noescape
func siphashCore(h *hashFunc, p []uint8)

// finish the hash calculation
//go:noescape
func siphashFinalize(h *hashFunc) uint64
