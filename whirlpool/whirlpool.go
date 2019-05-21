package whirlpool

//  The Whirlpool hashing function.
//
//  Original implementation by Paulo S. L. M. Barreto and Vincent Rijmen.
//    P.S.L.M. Barreto, V. Rijmen,
//    ``The Whirlpool hashing function,''
//    NESSIE submission, 2000 (tweaked version, 2001),
//    https://github.com/torvalds/linux/blob/master/crypto/wp512.c
import (
	"fmt"
)

func HashOfBytes(ar []byte, salt []byte) []byte {
	var input []byte
	input = append(input, salt[:]...)
	input = append(input, ar...)
	var hash = Sum512(input)
	return hash[:]
}

func HashOfString(s string, salt []byte) []byte {
	var input []byte
	input = append(input, salt[:]...)
	input = append(input, []byte(s)...)
	var hash = Sum512(input)
	return hash[:]
}

func Sum512(data []byte) [cDigestBytes]byte {
	var hash = New()
	appendBytes(data, uint64(8*len(data)), &hash)
	var digest [cDigestBytes]byte
	finalize(&hash, digest[:])
	return digest
}

type Hash struct {
	bitLength  [cLengthBytes]byte
	buffer     [cWBlockBytes]byte
	bufferBits int
	bufferPos  int
	hash       [cDigestBytes / 8]uint64
}

func New() Hash {
	var ret Hash
	if cTraceIntermediateValues {
		fmt.Printf("Initial hash value:" + LB)
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X"+LB,
				byte(ret.hash[i]>>56),
				byte(ret.hash[i]>>48),
				byte(ret.hash[i]>>40),
				byte(ret.hash[i]>>32),
				byte(ret.hash[i]>>24),
				byte(ret.hash[i]>>16),
				byte(ret.hash[i]>>8),
				byte(ret.hash[i]))
		}
		fmt.Printf(LB)
	}
	return ret
}

func (ob *Hash) Write(data []byte) (n int, err error) {
	appendBytes(data, uint64(8*len(data)), ob)
	return len(data), nil
}

func appendBytes(source []byte, sourceBits uint64, ob *Hash) {
	var sourcePos = 0
	var sourceGap = (8 - int(sourceBits)&7) & 7
	var bufferRem = ob.bufferBits & 7
	var b uint32
	var buffer = ob.buffer[:]
	var bitLength = &ob.bitLength
	var bufferBits = ob.bufferBits
	var bufferPos = ob.bufferPos
	{
		var carry = uint32(0)
		var val = uint64(sourceBits)
		for i := 31; i >= 0 && (carry != 0 || val != 0); i-- {
			carry += uint32(bitLength[i]) + (uint32(val) & 0xff)
			bitLength[i] = byte(carry)
			carry >>= 8
			val >>= 8
		}
	}
	for sourceBits > 8 {
		b = uint32((source[sourcePos]<<uint32(sourceGap))&0xff) |
			uint32((source[sourcePos+1]&0xff)>>uint32(8-sourceGap))
		buffer[bufferPos] |= byte(b >> uint32(bufferRem))
		bufferPos++
		bufferBits += 8 - bufferRem
		if bufferBits == cDigestBits {
			processBuffer(ob)
			bufferBits = 0
			bufferPos = 0
		}
		buffer[bufferPos] = byte(b << uint32(8-bufferRem))
		bufferBits += bufferRem
		sourceBits -= 8
		sourcePos++
	}
	if sourceBits > 0 {
		b = uint32(source[sourcePos]<<uint32(sourceGap)) & 0xff
		// bits are left-justified on b.
		// process the remaining bits:
		buffer[bufferPos] |= byte(b) >> uint32(bufferRem)
	} else {
		b = 0
	}
	if uint64(bufferRem)+sourceBits < 8 {
		// all remaining data fits on buffer[bufferPos],
		// and there still remains some space.
		bufferBits += int(sourceBits)
	} else {
		// buffer[bufferPos] is full:
		bufferPos++
		bufferBits += 8 - bufferRem // bufferBits = 8*bufferPos
		sourceBits -= uint64(8 - bufferRem)
		// now 0 <= sourceBits < 8
		// furthermore, all data (if any is left) is in source[sourcePos].
		if bufferBits == cDigestBits {
			// process data block:
			processBuffer(ob)
			// reset buffer:
			bufferBits = 0
			bufferPos = 0
		}
		buffer[bufferPos] = byte(b << uint32(8-bufferRem))
		bufferBits += int(sourceBits)
	}
	ob.bufferBits = bufferBits
	ob.bufferPos = bufferPos
}

func finalize(ob *Hash, result []byte) {
	var buffer = ob.buffer[:]
	var bufferBits = ob.bufferBits
	var bufferPos = ob.bufferPos
	var digest = result
	// append a '1'-bit:
	buffer[bufferPos] |= 0x80 >> uint32(bufferBits&7)
	bufferPos++ // all remaining bits on the current byte are set to zero.
	// pad with zero bits to complete (N*cWBlockBits - cLengthBits) bits:
	if bufferPos > cWBlockBytes-cLengthBytes {
		if bufferPos < cWBlockBytes {
			for i := bufferPos; i < cWBlockBytes; i++ {
				buffer[i] = 0
			}
		}
		processBuffer(ob) // process data block
		bufferPos = 0     // reset buffer
	}
	if bufferPos < cWBlockBytes-cLengthBytes {
		for i := bufferPos; i < cWBlockBytes-cLengthBytes; i++ {
			buffer[i] = 0
		}
	}
	bufferPos = cWBlockBytes - cLengthBytes
	// append bit length of hashed data
	var bitLength = ob.bitLength[:]
	copy(buffer[cWBlockBytes-cLengthBytes:], bitLength[:cLengthBytes])
	//
	// process data block
	processBuffer(ob)
	//
	// return the completed message digest:
	for i, b := 0, 0; i < cDigestBytes/8; i++ {
		digest[b+0] = byte(ob.hash[i] >> 56)
		digest[b+1] = byte(ob.hash[i] >> 48)
		digest[b+2] = byte(ob.hash[i] >> 40)
		digest[b+3] = byte(ob.hash[i] >> 32)
		digest[b+4] = byte(ob.hash[i] >> 24)
		digest[b+5] = byte(ob.hash[i] >> 16)
		digest[b+6] = byte(ob.hash[i] >> 8)
		digest[b+7] = byte(ob.hash[i])
		b += 8
	}
	ob.bufferBits = bufferBits
	ob.bufferPos = bufferPos
}

func processBuffer(ob *Hash) {
	var K [8]uint64     // the round key
	var block [8]uint64 // mu(buffer)
	var state [8]uint64 // the cipher state
	var L [8]uint64
	var buffer = ob.buffer[:]
	if cTraceIntermediateValues {
		fmt.Printf("The 8x8 matrix Z' derived from the" +
			" data-string is as follows." + LB)
		for i, b := 0, 0; i < cWBlockBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X"+LB,
				buffer[b+0], buffer[b+1], buffer[b+2], buffer[b+3],
				buffer[b+4], buffer[b+5], buffer[b+6], buffer[b+7])
			b += 8
		}
		fmt.Printf(LB)
		buffer = ob.buffer[:]
	}
	// map the buffer to a block:
	for i, b := 0, 0; i < 8; i++ {
		block[i] = ((uint64(buffer[b+0])) << 56) ^
			((uint64(buffer[b+1]) & 0xff) << 48) ^
			((uint64(buffer[b+2]) & 0xff) << 40) ^
			((uint64(buffer[b+3]) & 0xff) << 32) ^
			((uint64(buffer[b+4]) & 0xff) << 24) ^
			((uint64(buffer[b+5]) & 0xff) << 16) ^
			((uint64(buffer[b+6]) & 0xff) << 8) ^
			(uint64(buffer[b+7]) & 0xff)
		b += 8
	}
	// compute and apply K^0 to the cipher state:
	for i := 0; i < 8; i++ {
		K[i] = ob.hash[i]
		state[i] = block[i] ^ K[i]
	}
	if cTraceIntermediateValues {
		fmt.Printf("The K_0 matrix (from the initialization value IV)" +
			" and X'' matrix are as follows." + LB)
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf(
				"    %02X %02X %02X %02X %02X %02X %02X %02X    "+
					"    %02X %02X %02X %02X %02X %02X %02X %02X"+LB,
				byte(K[i]>>56),
				byte(K[i]>>48),
				byte(K[i]>>40),
				byte(K[i]>>32),
				byte(K[i]>>24),
				byte(K[i]>>16),
				byte(K[i]>>8),
				byte(K[i]),
				byte(state[i]>>56),
				byte(state[i]>>48),
				byte(state[i]>>40),
				byte(state[i]>>32),
				byte(state[i]>>24),
				byte(state[i]>>16),
				byte(state[i]>>8),
				byte(state[i]),
			)
		}
		fmt.Printf(LB +
			"The following are (hexadecimal representations of) the" +
			" successive values of the variables" +
			" K_i for i = 1 to 10 and W'." + LB + LB)
	}
	// iterate over all rounds:
	for r := 1; r <= cRounds; r++ {
		// compute K^r from K^{r-1}:
		L[0] = cC0[int(K[0]>>56)] ^
			cC1[int(K[7]>>48)&0xff] ^
			cC2[int(K[6]>>40)&0xff] ^
			cC3[int(K[5]>>32)&0xff] ^
			cC4[int(K[4]>>24)&0xff] ^
			cC5[int(K[3]>>16)&0xff] ^
			cC6[int(K[2]>>8)&0xff] ^
			cC7[int(K[1])&0xff] ^
			rc[r]
		L[1] = cC0[int(K[1]>>56)] ^
			cC1[int(K[0]>>48)&0xff] ^
			cC2[int(K[7]>>40)&0xff] ^
			cC3[int(K[6]>>32)&0xff] ^
			cC4[int(K[5]>>24)&0xff] ^
			cC5[int(K[4]>>16)&0xff] ^
			cC6[int(K[3]>>8)&0xff] ^
			cC7[int(K[2])&0xff]
		L[2] = cC0[int(K[2]>>56)] ^
			cC1[int(K[1]>>48)&0xff] ^
			cC2[int(K[0]>>40)&0xff] ^
			cC3[int(K[7]>>32)&0xff] ^
			cC4[int(K[6]>>24)&0xff] ^
			cC5[int(K[5]>>16)&0xff] ^
			cC6[int(K[4]>>8)&0xff] ^
			cC7[int(K[3])&0xff]
		L[3] = cC0[int(K[3]>>56)] ^
			cC1[int(K[2]>>48)&0xff] ^
			cC2[int(K[1]>>40)&0xff] ^
			cC3[int(K[0]>>32)&0xff] ^
			cC4[int(K[7]>>24)&0xff] ^
			cC5[int(K[6]>>16)&0xff] ^
			cC6[int(K[5]>>8)&0xff] ^
			cC7[int(K[4])&0xff]
		L[4] = cC0[int(K[4]>>56)] ^
			cC1[int(K[3]>>48)&0xff] ^
			cC2[int(K[2]>>40)&0xff] ^
			cC3[int(K[1]>>32)&0xff] ^
			cC4[int(K[0]>>24)&0xff] ^
			cC5[int(K[7]>>16)&0xff] ^
			cC6[int(K[6]>>8)&0xff] ^
			cC7[int(K[5])&0xff]
		L[5] = cC0[int(K[5]>>56)] ^
			cC1[int(K[4]>>48)&0xff] ^
			cC2[int(K[3]>>40)&0xff] ^
			cC3[int(K[2]>>32)&0xff] ^
			cC4[int(K[1]>>24)&0xff] ^
			cC5[int(K[0]>>16)&0xff] ^
			cC6[int(K[7]>>8)&0xff] ^
			cC7[int(K[6])&0xff]
		L[6] = cC0[int(K[6]>>56)] ^
			cC1[int(K[5]>>48)&0xff] ^
			cC2[int(K[4]>>40)&0xff] ^
			cC3[int(K[3]>>32)&0xff] ^
			cC4[int(K[2]>>24)&0xff] ^
			cC5[int(K[1]>>16)&0xff] ^
			cC6[int(K[0]>>8)&0xff] ^
			cC7[int(K[7])&0xff]
		L[7] = cC0[int(K[7]>>56)] ^
			cC1[int(K[6]>>48)&0xff] ^
			cC2[int(K[5]>>40)&0xff] ^
			cC3[int(K[4]>>32)&0xff] ^
			cC4[int(K[3]>>24)&0xff] ^
			cC5[int(K[2]>>16)&0xff] ^
			cC6[int(K[1]>>8)&0xff] ^
			cC7[int(K[0])&0xff]
		K[0] = L[0]
		K[1] = L[1]
		K[2] = L[2]
		K[3] = L[3]
		K[4] = L[4]
		K[5] = L[5]
		K[6] = L[6]
		K[7] = L[7]
		// apply the r-th round transformation:
		L[0] = cC0[int(state[0]>>56)] ^
			cC1[int(state[7]>>48)&0xff] ^
			cC2[int(state[6]>>40)&0xff] ^
			cC3[int(state[5]>>32)&0xff] ^
			cC4[int(state[4]>>24)&0xff] ^
			cC5[int(state[3]>>16)&0xff] ^
			cC6[int(state[2]>>8)&0xff] ^
			cC7[int(state[1])&0xff] ^
			K[0]
		L[1] = cC0[int(state[1]>>56)] ^
			cC1[int(state[0]>>48)&0xff] ^
			cC2[int(state[7]>>40)&0xff] ^
			cC3[int(state[6]>>32)&0xff] ^
			cC4[int(state[5]>>24)&0xff] ^
			cC5[int(state[4]>>16)&0xff] ^
			cC6[int(state[3]>>8)&0xff] ^
			cC7[int(state[2])&0xff] ^
			K[1]
		L[2] = cC0[int(state[2]>>56)] ^
			cC1[int(state[1]>>48)&0xff] ^
			cC2[int(state[0]>>40)&0xff] ^
			cC3[int(state[7]>>32)&0xff] ^
			cC4[int(state[6]>>24)&0xff] ^
			cC5[int(state[5]>>16)&0xff] ^
			cC6[int(state[4]>>8)&0xff] ^
			cC7[int(state[3])&0xff] ^
			K[2]
		L[3] = cC0[int(state[3]>>56)] ^
			cC1[int(state[2]>>48)&0xff] ^
			cC2[int(state[1]>>40)&0xff] ^
			cC3[int(state[0]>>32)&0xff] ^
			cC4[int(state[7]>>24)&0xff] ^
			cC5[int(state[6]>>16)&0xff] ^
			cC6[int(state[5]>>8)&0xff] ^
			cC7[int(state[4])&0xff] ^
			K[3]
		L[4] = cC0[int(state[4]>>56)] ^
			cC1[int(state[3]>>48)&0xff] ^
			cC2[int(state[2]>>40)&0xff] ^
			cC3[int(state[1]>>32)&0xff] ^
			cC4[int(state[0]>>24)&0xff] ^
			cC5[int(state[7]>>16)&0xff] ^
			cC6[int(state[6]>>8)&0xff] ^
			cC7[int(state[5])&0xff] ^
			K[4]
		L[5] = cC0[int(state[5]>>56)] ^
			cC1[int(state[4]>>48)&0xff] ^
			cC2[int(state[3]>>40)&0xff] ^
			cC3[int(state[2]>>32)&0xff] ^
			cC4[int(state[1]>>24)&0xff] ^
			cC5[int(state[0]>>16)&0xff] ^
			cC6[int(state[7]>>8)&0xff] ^
			cC7[int(state[6])&0xff] ^
			K[5]
		L[6] = cC0[int(state[6]>>56)] ^
			cC1[int(state[5]>>48)&0xff] ^
			cC2[int(state[4]>>40)&0xff] ^
			cC3[int(state[3]>>32)&0xff] ^
			cC4[int(state[2]>>24)&0xff] ^
			cC5[int(state[1]>>16)&0xff] ^
			cC6[int(state[0]>>8)&0xff] ^
			cC7[int(state[7])&0xff] ^
			K[6]
		L[7] = cC0[int(state[7]>>56)] ^
			cC1[int(state[6]>>48)&0xff] ^
			cC2[int(state[5]>>40)&0xff] ^
			cC3[int(state[4]>>32)&0xff] ^
			cC4[int(state[3]>>24)&0xff] ^
			cC5[int(state[2]>>16)&0xff] ^
			cC6[int(state[1]>>8)&0xff] ^
			cC7[int(state[0])&0xff] ^
			K[7]
		state[0] = L[0]
		state[1] = L[1]
		state[2] = L[2]
		state[3] = L[3]
		state[4] = L[4]
		state[5] = L[5]
		state[6] = L[6]
		state[7] = L[7]
		if cTraceIntermediateValues {
			fmt.Printf("i = %d:"+LB, r)
			for i := 0; i < cDigestBytes/8; i++ {
				fmt.Printf(
					"    %02X %02X %02X %02X %02X %02X %02X %02X        "+
						"%02X %02X %02X %02X %02X %02X %02X %02X"+LB,
					byte(K[i]>>56),
					byte(K[i]>>48),
					byte(K[i]>>40),
					byte(K[i]>>32),
					byte(K[i]>>24),
					byte(K[i]>>16),
					byte(K[i]>>8),
					byte(K[i]),
					byte(state[i]>>56),
					byte(state[i]>>48),
					byte(state[i]>>40),
					byte(state[i]>>32),
					byte(state[i]>>24),
					byte(state[i]>>16),
					byte(state[i]>>8),
					byte(state[i]),
				)
			}
			fmt.Printf(LB)
		}
	}
	// apply the Miyaguchi-Preneel compression function:
	ob.hash[0] ^= state[0] ^ block[0]
	ob.hash[1] ^= state[1] ^ block[1]
	ob.hash[2] ^= state[2] ^ block[2]
	ob.hash[3] ^= state[3] ^ block[3]
	ob.hash[4] ^= state[4] ^ block[4]
	ob.hash[5] ^= state[5] ^ block[5]
	ob.hash[6] ^= state[6] ^ block[6]
	ob.hash[7] ^= state[7] ^ block[7]
	if cTraceIntermediateValues {
		fmt.Printf("The value of Y' output from the" +
			" round-function is as follows." + LB)
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X"+LB,
				byte(ob.hash[i]>>56),
				byte(ob.hash[i]>>48),
				byte(ob.hash[i]>>40),
				byte(ob.hash[i]>>32),
				byte(ob.hash[i]>>24),
				byte(ob.hash[i]>>16),
				byte(ob.hash[i]>>8),
				byte(ob.hash[i]))
		}
		fmt.Printf(LB)
	}
}

func padHexToString(ar []byte) (ret string) {
	for i := 0; i < len(ar); i++ {
		ret += fmt.Sprintf("%02X", ar[i])
	}
	return ret
}
