package mask

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestSkipJack32InitClassic(t *testing.T) {
	skipJack := SkipJack32{}

	_ = skipJack.Init("SECRET_KEY", binary.LittleEndian)

	expectedKeyAsciiValues := [10]uint32{83, 69, 67, 82, 69, 84, 95, 75, 69, 89}

	if !reflect.DeepEqual(expectedKeyAsciiValues, skipJack.keyAsciiValues) {
		t.Errorf("Expected %v, got %v", expectedKeyAsciiValues, skipJack.keyAsciiValues)
	}
}

func TestG(t *testing.T) {
	skipJack := SkipJack32{}
	_ = skipJack.Init("SECRET_KEY", binary.LittleEndian)

	AssertEqualsU32(t, 16064, skipJack.g(skipJack.keyAsciiValues, 0, 0))
	AssertEqualsU32(t, 54072, skipJack.g(skipJack.keyAsciiValues, 1, 0))
	AssertEqualsU32(t, 65155, skipJack.g(skipJack.keyAsciiValues, 0, 1))
	AssertEqualsU32(t, 2492, skipJack.g(skipJack.keyAsciiValues, 1, 1))
	AssertEqualsU32(t, 7571, skipJack.g(skipJack.keyAsciiValues, 2, 1))
	AssertEqualsU32(t, 21650, skipJack.g(skipJack.keyAsciiValues, 1, 2))
	AssertEqualsU32(t, 44711, skipJack.g(skipJack.keyAsciiValues, 0, math.MaxUint32))
	AssertEqualsU32(t, 8379, skipJack.g(skipJack.keyAsciiValues, 1<<30-1, 0))
}

func TestProcess(t *testing.T) {
	skipJack := SkipJack32{}
	_ = skipJack.Init("SECRET_KEY", binary.LittleEndian)

	AssertEqualsU32(t, 4130141102, skipJack.Process(0, true))
	AssertEqualsU32(t, 3101515088, skipJack.Process(0, false))
	AssertEqualsU32(t, 352711532, skipJack.Process(1, true))
	AssertEqualsU32(t, 34507870, skipJack.Process(1, false))
	AssertEqualsU32(t, 2049254042, skipJack.Process(2, true))
	AssertEqualsU32(t, 4263131063, skipJack.Process(2, false))
}

func TestProcessUnrolled(t *testing.T) {
	skipJack := SkipJack32{}
	_ = skipJack.Init("SECRET_KEY", binary.LittleEndian)

	AssertEqualsU32(t, 4130141102, skipJack.ProcessUnrolled(0, true))
	AssertEqualsU32(t, 3101515088, skipJack.ProcessUnrolled(0, false))
	AssertEqualsU32(t, 352711532, skipJack.ProcessUnrolled(1, true))
	AssertEqualsU32(t, 34507870, skipJack.ProcessUnrolled(1, false))
	AssertEqualsU32(t, 2049254042, skipJack.ProcessUnrolled(2, true))
	AssertEqualsU32(t, 4263131063, skipJack.ProcessUnrolled(2, false))
}

func AssertEqualsU32(t *testing.T, expected, actual uint32) {
	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}
