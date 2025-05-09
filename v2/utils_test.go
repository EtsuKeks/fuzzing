package jd

import (
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func TestComputeDepth_Correctness(t *testing.T) {
	cases := []struct {
		val      interface{}
		expected int
	}{
		{val: 42, expected: 0},
		{val: "hello", expected: 0},
		{val: []interface{}{1, 2, 3}, expected: 1},
		{val: map[string]interface{}{"a": 1, "b": 2}, expected: 1},
		{val: []interface{}{[]interface{}{"x"}, 2}, expected: 2},
		{val: map[string]interface{}{"a": map[string]interface{}{"b": []interface{}{nil}}}, expected: 3},
	}

	for _, c := range cases {
		if got := computeDepth(c.val); got != c.expected {
			t.Errorf("computeDepth(%#v) = %d; want %d", c.val, got, c.expected)
		}
	}
}

func TestMutations(t *testing.T) {
	cons := fuzzhdr.NewConsumer([]byte("hello world seed bytes"))
	orig := []byte(". as {$a} ?// [$a] ?// $a | $a")
	m, err := mutateBytesArr(orig, cons)
	if err != nil {
		t.Fatalf("MutateBytesArr returned error: %v", err)
	}

	if len(orig) != len(m) {
		t.Errorf("Mutated array differs from the original in length, original length: %v, mutated length: %v",
			len(orig), len(m))
	}

	count := 0
	for i := range orig {
		if orig[i] != m[i] {
			count++
		}
	}

	if count >= 10 {
		t.Errorf("Mutated array differs from the original in more than 10 places, original: %v, mutated: %v",
			orig, m)
	}
}
