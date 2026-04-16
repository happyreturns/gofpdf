/*
 * Copyright (c) 2013-2014 Kurt Jung (Gmail: kurt.w.jung)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// PDF protection is adapted from the work of Klemen VODOPIVEC for the fpdf
// product.

package gofpdf

import (
	"crypto/md5" //nolint:gosec // MD5 is required by the PDF Standard Security Handler algorithm
	// (ISO 32000-1 §7.6.3). This is a spec-mandated usage, not a
	// general-purpose security choice. The Veracode CWE-327 finding for
	// this file (CF-6624) must be mitigated at the Veracode platform level
	// as "Mitigated by Design": the RC4+MD5 key derivation is defined by
	// the PDF 1.x specification and cannot be replaced without breaking
	// compatibility with all conforming PDF readers.
	"crypto/rc4"
	"encoding/binary"
	"math/rand"
)

// Advisory bitflag constants that control document activities
const (
	CnProtectPrint      = 4
	CnProtectModify     = 8
	CnProtectCopy       = 16
	CnProtectAnnotForms = 32
)

type protectType struct {
	encrypted     bool
	uValue        []byte
	oValue        []byte
	pValue        int
	padding       []byte
	encryptionKey []byte
	objNum        int
	rc4cipher     *rc4.Cipher
	rc4n          uint32 // Object number associated with rc4 cipher
}

func (p *protectType) rc4(n uint32, buf *[]byte) {
	if p.rc4cipher == nil || p.rc4n != n {
		p.rc4cipher, _ = rc4.NewCipher(p.objectKey(n))
		p.rc4n = n
	}
	p.rc4cipher.XORKeyStream(*buf, *buf)
}

func (p *protectType) objectKey(n uint32) []byte {
	var nbuf, b []byte
	nbuf = make([]byte, 8, 8)
	binary.LittleEndian.PutUint32(nbuf, n)
	b = append(b, p.encryptionKey...)
	b = append(b, nbuf[0], nbuf[1], nbuf[2], 0, 0)
	s := md5.Sum(b) //nolint:gosec // spec-mandated: ISO 32000-1 §7.6.3.3 Algorithm 1
	return s[0:10]
}

func oValueGen(userPass, ownerPass []byte) (v []byte) {
	var c *rc4.Cipher
	tmp := md5.Sum(ownerPass) //nolint:gosec // spec-mandated: ISO 32000-1 §7.6.3.4 Algorithm 3 step (a)
	c, _ = rc4.NewCipher(tmp[0:5])
	size := len(userPass)
	v = make([]byte, size, size)
	c.XORKeyStream(v, userPass)
	return
}

func (p *protectType) uValueGen() (v []byte) {
	var c *rc4.Cipher
	c, _ = rc4.NewCipher(p.encryptionKey)
	size := len(p.padding)
	v = make([]byte, size, size)
	c.XORKeyStream(v, p.padding)
	return
}

func (p *protectType) setProtection(privFlag byte, userPassStr, ownerPassStr string) {
	privFlag = 192 | (privFlag & (CnProtectCopy | CnProtectModify | CnProtectPrint | CnProtectAnnotForms))
	p.padding = []byte{
		0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
		0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
		0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
		0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
	}
	userPass := []byte(userPassStr)
	var ownerPass []byte
	if ownerPassStr == "" {
		ownerPass = make([]byte, 8, 8)
		binary.LittleEndian.PutUint64(ownerPass, uint64(rand.Int63()))
	} else {
		ownerPass = []byte(ownerPassStr)
	}
	userPass = append(userPass, p.padding...)[0:32]
	ownerPass = append(ownerPass, p.padding...)[0:32]
	p.encrypted = true
	p.oValue = oValueGen(userPass, ownerPass)
	var buf []byte
	buf = append(buf, userPass...)
	buf = append(buf, p.oValue...)
	buf = append(buf, privFlag, 0xff, 0xff, 0xff)
	sum := md5.Sum(buf) //nolint:gosec // spec-mandated: ISO 32000-1 §7.6.3.3 Algorithm 2 step (d)
	p.encryptionKey = sum[0:5]
	p.uValue = p.uValueGen()
	p.pValue = -(int(privFlag^255) + 1)
}
