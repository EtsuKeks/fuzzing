package jd

import (
	"errors"
	"math"
	"strings"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func computeDepth(val interface{}) int {
	switch v := val.(type) {
	case map[string]interface{}:
		max := 0
		for _, child := range v {
			if d := computeDepth(child); d > max {
				max = d
			}
		}
		return max + 1
	case []interface{}:
		max := 0
		for _, child := range v {
			if d := computeDepth(child); d > max {
				max = d
			}
		}
		return max + 1
	default:
		return 0
	}
}

func mutateBytesArr(b []byte, cons *fuzzhdr.ConsumeFuzzer) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	count, err := getRandomIntUpToN(cons, 10)
	if err != nil {
		return nil, err
	}
	for range count {
		pos, err := getRandomIntUpToN(cons, len(b))
		if err != nil {
			return nil, err
		}
		v, err := cons.GetByte()
		if err != nil {
			return nil, err
		}
		b[pos] ^= v
	}
	return b, nil
}

func getRandomIntUpToN(cons *fuzzhdr.ConsumeFuzzer, num int) (int, error) {
	if num <= 0 {
		return 0, errors.New("invalid upper bound for random int")
	}
	idx, err := cons.GetInt()
	if err != nil {
		return 0, err
	}
	return (idx%num + num) % num, nil
}

func getString(cons *fuzzhdr.ConsumeFuzzer, maxBytes int) (string, error) {
	nBytes, err := getRandomIntUpToN(cons, maxBytes)
	if err != nil {
		return "", err
	}
	stringInBytes, err := cons.GetNBytes(nBytes)
	if err != nil {
		return "", err
	}
	return string(stringInBytes), nil
}

func getFloat32(cons *fuzzhdr.ConsumeFuzzer) (float32, error) {
	f, err := cons.GetFloat32()
	if err != nil {
		return 0.0, err
	}
	if math.IsNaN(float64(f)) {
		return 0.0, nil
	}
	if math.IsInf(float64(f), 0) {
		return 0.0, nil
	}
	return f, nil
}

func getFloat64(cons *fuzzhdr.ConsumeFuzzer) (float64, error) {
	f, err := cons.GetFloat64()
	if err != nil {
		return 0.0, err
	}
	if math.IsNaN(f) {
		return 0.0, nil
	}
	if math.IsInf(f, 0) {
		return 0.0, nil
	}
	return f, nil
}

func repeatSeed(seed string, n int) []byte {
	return []byte(strings.Repeat(seed, n))
}

func shuffle(cons *fuzzhdr.ConsumeFuzzer, n int, swap func(i int, j int)) error {
	for i := range n {
		j, err := getRandomIntUpToN(cons, n)
		if err != nil {
			return err
		}
		swap(i, j)
	}
	return nil
}
