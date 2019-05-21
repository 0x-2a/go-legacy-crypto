package mask

//  This modules implements the SKIP32 integer obfuscator:
//    SKIP32 Id Obfuscator: Greg Rose, 1999
//      http://www.cpan.org/authors/id/E/ES/ESH/Crypt-Skip32-0.16.readme
//    SKIPJACK and KEA: Mark Tillotson, Panu Rissanen, 1998
//      http://web.mit.edu/freebsd/head/sys/opencrypto/skipjack.c
import (
	"encoding/binary"
	"fmt"
)

const (
	keyLength    = 10
	fTableLength = 256
)

type SkipJack32 struct {
	keyAsciiValues [keyLength]uint32
	byteOrder      binary.ByteOrder
	fTable         [fTableLength]uint32
}

func (s *SkipJack32) Init(seed string, byteOrder binary.ByteOrder) error {
	s.fTable = getInitialSkipjackFTable()

	s.byteOrder = byteOrder
	if s.byteOrder == nil {
		return fmt.Errorf("error: expected byteOrder but nil supplied")
	}

	keyBytes := []byte(seed)
	if len(seed) < keyLength {
		return fmt.Errorf("error: expected keylength > %d, actual: %d", keyLength, len(seed))
	}

	var key0 = keyBytes[0:keyLength]
	for i, b := range key0 {
		s.keyAsciiValues[i] = uint32(b)
	}

	return nil
}

func (s *SkipJack32) g(key [keyLength]uint32, k uint32, w uint32) uint32 {
	if k < 0 {
		panic("Negative k values will cause range errors.")
	}

	// Prevent uint32 overflow
	// 2^32 positive uint32's minus the 2^2 `k4` = 2^29
	if k >= 1<<30 {
		panic("K value too high, will overflow to small integers.")
	}

	g1 := (w >> 8) & 0xff
	g2 := w & 0xff
	var g3, g4, g5, g6 uint32
	k4 := 4 * k

	g3 = s.fTable[g2^s.keyAsciiValues[k4%keyLength]] ^ g1
	g4 = s.fTable[g3^s.keyAsciiValues[(k4+1)%keyLength]] ^ g2
	g5 = s.fTable[g4^s.keyAsciiValues[(k4+2)%keyLength]] ^ g3
	g6 = s.fTable[g5^s.keyAsciiValues[(k4+3)%keyLength]] ^ g4

	return (g5 << 8) + g6
}

func (s *SkipJack32) Process(num32 uint32, encrypt bool) uint32 {
	// k = encryption round number
	// i = encryption round counter

	// sort out direction
	k := uint32(23)
	if encrypt {
		k = 0
	}

	// pack into words
	wl := (num32 >> 16) & 0xffff
	wr := num32 & 0xffff
	if s.byteOrder == binary.BigEndian {
		wl = ((num32 << 8) & 0xff00) + ((num32 >> 8) & 0xff)
		wr = ((num32 >> 8) & 0xff00) + ((num32 >> 24) & 0xff)
	}

	// 24 feistel rounds, doubled up
	for i := 0; i < 12; i++ {
		wr = wr ^ s.g(s.keyAsciiValues, k, wl) ^ k
		k += 1
		if !encrypt {
			k -= 2
		}

		wl = wl ^ s.g(s.keyAsciiValues, k, wr) ^ k
		k += 1
		if !encrypt {
			k -= 2
		}
	}

	// implicitly swap halves while unpacking
	if s.byteOrder == binary.LittleEndian {
		return (wr << 16) + wl
	}

	return (((wr >> 8) & 0xff) + ((wr << 8) & 0xff00) + ((wl << 8) & 0xff0000) + (wl << 24)) & 0xffffffff
}

func (s *SkipJack32) ProcessUnrolled(num32 uint32, encrypt bool) uint32 {
	// k = round number
	// i = round counter

	// sort out direction
	k := uint32(0)
	if !encrypt {
		k = uint32(23 * 4)
	}

	// This is specific to 32 bit unsigned integers
	// pack into words, e.g.     num32 = 1110001110001110 0101010101010101
	wl := (num32 >> 16) & 0xffff // wl = 0000000000000000 1110001110001110
	wr := num32 & 0xffff         // wr = 0000000000000000 0101010101010101
	if s.byteOrder == binary.BigEndian {
		wl = ((num32 << 8) & 0xff00) + ((num32 >> 8) & 0xff)
		wr = ((num32 >> 8) & 0xff00) + ((num32 >> 24) & 0xff)
	}

	// 24 feistel rounds, doubled up
	// NOTE: inlining g(x) results in ~42% faster code.  unrolling further doesn't make it any faster
	// using KEYLEN instead of a hardcoded number results in ~18% slower code
	for i := 0; i < 12; i++ {
		g1 := (wl >> 8) & 0xff
		g2 := wl & 0xff
		g3 := s.fTable[g2^s.keyAsciiValues[(k)%10]] ^ g1
		g4 := s.fTable[g3^s.keyAsciiValues[(k+1)%10]] ^ g2
		g5 := s.fTable[g4^s.keyAsciiValues[(k+2)%10]] ^ g3
		g6 := s.fTable[g5^s.keyAsciiValues[(k+3)%10]] ^ g4
		wr = wr ^ ((g5 << 8) + g6) ^ (k >> 2)
		k += 4
		if !encrypt {
			k -= 8
		}

		g1 = (wr >> 8) & 0xff
		g2 = wr & 0xff
		g3 = s.fTable[g2^s.keyAsciiValues[(k)%10]] ^ g1
		g4 = s.fTable[g3^s.keyAsciiValues[(k+1)%10]] ^ g2
		g5 = s.fTable[g4^s.keyAsciiValues[(k+2)%10]] ^ g3
		g6 = s.fTable[g5^s.keyAsciiValues[(k+3)%10]] ^ g4
		wl = wl ^ ((g5 << 8) + g6) ^ (k >> 2)
		k += 4
		if !encrypt {
			k -= 8
		}
	}

	// implicitly swap halves while unpacking
	if s.byteOrder == binary.LittleEndian {
		return (wr << 16) + wl
	}

	return (((wr >> 8) & 0xff) + ((wr << 8) & 0xff00) + ((wl << 8) & 0xff0000) + (wl << 24)) & 0xffffffff
}

func getInitialSkipjackFTable() [fTableLength]uint32 {
	return [fTableLength]uint32{
		0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
		0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
		0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
		0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
		0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
		0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
		0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
		0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
		0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
		0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
		0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
		0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
		0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
		0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
		0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
		0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
	}
}
