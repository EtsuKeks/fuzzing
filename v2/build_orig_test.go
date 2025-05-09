package jd

import (
	"encoding/json"
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func TestBuildJSON_DepthBound_And_ValidJSON(t *testing.T) {
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
	for maxD := range 10 {
		val, err := BuildJSON(cons, maxD)
		if err != nil {
			t.Errorf("BuildJSON returned error for maxDepth=%d: %v", maxD, err)
			continue
		}
		if got := computeDepth(val); got > maxD {
			t.Errorf("BuildJSON produced depth %d > maxDepth %d", got, maxD)
		}

		_, err = json.Marshal(val)
		if err != nil {
			t.Errorf("BuildJSON with maxDepth=%d produced invalid JSON: %v", maxD, err)
		}
	}
}

func TestBuildJSON_PrimitiveAtZero_And_ValidJSON(t *testing.T) {
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
	for range 10 {
		val, err := BuildJSON(cons, 0)
		if err != nil {
			t.Errorf("BuildJSON returned error for maxDepth=0: %v", err)
			continue
		}
		switch val.(type) {
		case string, int, float32, float64, byte, uint, uint16, uint32, uint64:
		default:
			t.Errorf("Expected primitive at depth 0, got %T", val)
		}

		_, err = json.Marshal(val)
		if err != nil {
			t.Errorf("Primitive BuildJSON failed to marshal: %v (value %v)", err, val)
		}
	}
}
