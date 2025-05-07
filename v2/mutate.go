package jd

import (
	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func MutateJson(q string, cons *fuzzhdr.ConsumeFuzzer) string {
	b := []byte(q)
	if len(b) == 0 {
		return q
	}
	count := GetRandomIntUpToN(cons, 10)
	for i := 0; i < count; i++ {
		pos := GetRandomIntUpToN(cons, len(b))
		b[pos] ^= GetRandomByte(cons)
	}
	return string(b)
}
