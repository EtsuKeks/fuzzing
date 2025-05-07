package jd

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func TestBuildJSON_DepthBound_And_ValidJSON(t *testing.T) {
	cons := fuzzhdr.NewConsumer([]byte("hello world random seed"))
	for maxD := range 5 {
		val := BuildJSON(cons, maxD)
		if got := computeDepth(val); got > maxD {
			t.Errorf("BuildJSON produced depth %d > maxDepth %d", got, maxD)
		}

		_, err := json.Marshal(val)
		if err != nil {
			t.Errorf("BuildJSON with maxDepth=%d produced invalid JSON: %v", maxD, err)
		}
	}
}

func TestBuildJSON_PrimitiveAtZero_And_ValidJSON(t *testing.T) {
	cons := fuzzhdr.NewConsumer([]byte("hello world random seed"))
	for range 10 {
		val := BuildJSON(cons, 0)
		switch val.(type) {
		case string, int, float32, float64, byte, uint, uint16, uint32, uint64:
		default:
			t.Errorf("Expected primitive at depth 0, got %T", val)
		}

		_, err := json.Marshal(val)
		if err != nil {
			t.Errorf("Primitive BuildJSON failed to marshal: %v (value %v)", err, val)
		}
	}
}

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

func TestGenerateOverlapJSON_JSONValidity(t *testing.T) {
	cons := fuzzhdr.NewConsumer([]byte("hello world random seed"))
	orig := map[string]interface{}{
		"a": 1,
		"b": []interface{}{true, "two", nil},
		"c": map[string]interface{}{"d": "x"},
	}
	for _, params := range []struct {
		renameProb, mutateProb int
	}{
		{0, 0},
		{50, 0},
		{0, 50},
		{50, 50},
		{100, 100},
	} {
		comp := GenerateOverlapJSON(orig, cons, params.renameProb, params.mutateProb)
		_, err := json.Marshal(comp)
		if err != nil {
			t.Errorf("GenerateOverlapJSON(%d,%d) produced invalid JSON: %v", params.renameProb, params.mutateProb, err)
		}
	}
}

func TestGenerateOverlapJSON_FullMutate(t *testing.T) {
	seed := []byte("hello world random seed")
	cons := fuzzhdr.NewConsumer(seed)
	orig := map[string]interface{}{
		"x": 1,
		"y": []interface{}{true, false},
		"z": "foo",
	}
	comp := GenerateOverlapJSON(orig, cons, 0, 100)

	_, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("failed to marshal orig: %v", err)
	}
	_, err = json.Marshal(comp)
	if err != nil {
		t.Fatalf("failed to marshal comp: %v", err)
	}

	origLeaves := make(map[string]interface{})
	compLeaves := make(map[string]interface{})

	var collect func(val interface{}, prefix string, out map[string]interface{})
	collect = func(val interface{}, prefix string, out map[string]interface{}) {
		switch v := val.(type) {
		case map[string]interface{}:
			for k, c := range v {
				collect(c, prefix+"."+k, out)
			}
		case []interface{}:
			for i, c := range v {
				collect(c, fmt.Sprintf("%s[%d]", prefix, i), out)
			}
		default:
			out[prefix] = v
		}
	}
	collect(orig, "", origLeaves)
	collect(comp, "", compLeaves)

	changed := false
	for path, ov := range origLeaves {
		if cv, ok := compLeaves[path]; ok {
			if !reflect.DeepEqual(ov, cv) {
				changed = true
				break
			}
		} else {
			changed = true
			break
		}
	}
	if !changed {
		t.Errorf("Expected at least one leaf to change under full mutation, but all leaves are identical")
	}
}

func TestGenerateOverlapJSON_NoMutate_NoRename(t *testing.T) {
	seed := []byte("nomutate")
	cons := fuzzhdr.NewConsumer(seed)
	orig := map[string]interface{}{
		"a": 1,
		"b": []interface{}{2, 3},
	}
	comp := GenerateOverlapJSON(orig, cons, 0, 0)
	if !reflect.DeepEqual(comp, orig) {
		t.Errorf("Expected identical JSON, got diff: %v vs %v", comp, orig)
	}
}

func TestGenerateOverlapJSON_RenameKeys(t *testing.T) {
	seed := []byte("rename100")
	cons := fuzzhdr.NewConsumer(seed)
	orig := map[string]interface{}{
		"key1": 1,
		"key2": 2,
	}
	comp := GenerateOverlapJSON(orig, cons, 100, 0)
	for k := range comp.(map[string]interface{}) {
		if k == "key1" || k == "key2" {
			t.Errorf("Expected keys renamed, but found original key %q", k)
		}
	}
}

func TestMutations(t *testing.T) {
	cons := fuzzhdr.NewConsumer([]byte("hello world seed bytes"))
	orig := ". as {$a} ?// [$a] ?// $a | $a"
	mq := MutateJson(orig, cons)
	origInBytes := []byte(orig)
	mqInBytes := []byte(mq)
	if len(origInBytes) != len(mqInBytes) {
		t.Errorf("Mutated query differs from the original in length, original length: %v, mutated length: %v",
			len(origInBytes),
			len(mqInBytes))
	}

	count := 0
	for i := 0; i < len(origInBytes); i++ {
		if origInBytes[i] != mqInBytes[i] {
			count++
		}
	}

	if count >= 10 {
		t.Errorf("Mutated query differs from the original in more than 10 places, original: %v, mutated: %v",
			origInBytes,
			mqInBytes)
	}
}
