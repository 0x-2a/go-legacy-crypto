package ripemd320

import (
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

func TestRipemd320(t *testing.T) {
	// https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd320.txt
	assert320Hash(t, "", "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8")
	assert320Hash(t, "a", "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d")
	assert320Hash(t, "abc", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d")
	assert320Hash(t, "message digest", "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197")
	assert320Hash(t, "abcdefghijklmnopqrstuvwxyz", "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009")
	assert320Hash(t, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac")
	assert320Hash(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4")
	assert320Hash(t, strings.Repeat("1234567890", 8), "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42")
	assert320Hash(t, strings.Repeat("a", 1000000), "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66")
}

func assert320Hash(t *testing.T, input, expectedOutput string) {
	var h hash.Hash
	h = New()
	h.Write([]byte(input))
	actual := hex.EncodeToString(h.Sum(nil))
	if expectedOutput != actual {
		t.Errorf("Expected %v, got %v", expectedOutput, actual)
	}
}
