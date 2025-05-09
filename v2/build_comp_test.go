package jd

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func TestGenerateOverlapJSON_JSONValidity(t *testing.T) {
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
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
		comp, err := GenerateOverlapJSON(cons, orig, params.renameProb, params.mutateProb)
		if err != nil {
			t.Errorf("GenerateOverlapJSON(%d,%d) returned error: %v", params.renameProb, params.mutateProb, err)
			continue
		}
		_, err = json.Marshal(comp)
		if err != nil {
			t.Errorf("GenerateOverlapJSON(%d,%d) produced invalid JSON: %v", params.renameProb, params.mutateProb, err)
		}
	}
}

func TestGenerateOverlapJSON_FullMutate(t *testing.T) {
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
	orig := map[string]interface{}{
		"x": 1,
		"y": []interface{}{true, false},
		"z": "foo",
	}

	comp, err := GenerateOverlapJSON(cons, orig, 0, 100)
	if err != nil {
		t.Fatalf("GenerateOverlapJSON failed: %v", err)
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
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
	orig := map[string]interface{}{
		"a": 1,
		"b": []interface{}{2, 3},
	}
	comp, err := GenerateOverlapJSON(cons, orig, 0, 0)
	if err != nil {
		t.Errorf("GenerateOverlapJSON returned error: %v", err)
		return
	}
	_, err = json.Marshal(comp)
	if err != nil {
		t.Fatalf("failed to marshal comp: %v", err)
	}
	if !reflect.DeepEqual(comp, orig) {
		t.Errorf("Expected identical JSON, got diff: %v vs %v", comp, orig)
	}
}

func TestGenerateOverlapJSON_RenameKeys(t *testing.T) {
	cons := fuzzhdr.NewConsumer(repeatSeed("hello world random seed", 1000))
	orig := map[string]interface{}{
		"key1": 1,
		"key2": 2,
	}
	comp, err := GenerateOverlapJSON(cons, orig, 100, 0)
	if err != nil {
		t.Fatalf("GenerateOverlapJSON returned error: %v", err)
	}
	_, err = json.Marshal(comp)
	if err != nil {
		t.Fatalf("failed to marshal comp: %v", err)
	}
	compMap, ok := comp.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map[string]interface{}, got %T", comp)
	}
	for k := range compMap {
		if k == "key1" || k == "key2" {
			t.Errorf("Expected keys renamed, but found original key %q", k)
		}
	}
}
