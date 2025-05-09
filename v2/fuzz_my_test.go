package jd

import (
	"bytes"
	"encoding/json"
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzJdMy(f *testing.F) {
	f.Fuzz(fuzzMy)
}

func fuzzMy(t *testing.T, input []byte) {
	if len(input) == 0 {
		return
	}
	minLen := 1 << 15
	if len(input) < minLen {
		count := minLen / len(input)
		extended := bytes.Repeat(input, count)
		input = extended
	}
	cons := fuzzhdr.NewConsumer(input)
	const (
		maxDepth      = 3
		renameProb    = 20
		mutateProb    = 25
		mutateArrProb = 25
		swapProb      = 50
	)

	origVal, err := BuildJSON(cons, maxDepth)
	if err != nil {
		t.Fatalf("BuildJSON error: %v", err)
	}
	origBytes, err := json.Marshal(origVal)
	if err != nil {
		t.Fatalf("failed to marshal orig: %v", err)
	}

	compVal, err := GenerateOverlapJSON(cons, origVal, renameProb, mutateProb)
	if err != nil {
		t.Fatalf("GenerateOverlapJSON error: %v", err)
	}
	compBytes, err := json.Marshal(compVal)
	if err != nil {
		t.Fatalf("failed to marshal comp: %v", err)
	}

	n, err := getRandomIntUpToN(cons, 100)
	if err != nil {
		t.Fatalf("fuzzhdr consumer error: %v", err)
	}
	if n < mutateArrProb {
		origBytes, err = mutateBytesArr(origBytes, cons)
		if err != nil {
			t.Fatalf("MutateJson on orig failed: %v", err)
		}
	}

	n, err = getRandomIntUpToN(cons, 100)
	if err != nil {
		t.Fatalf("fuzzhdr consumer error: %v", err)
	}
	if n < mutateArrProb {
		compBytes, err = mutateBytesArr(compBytes, cons)
		if err != nil {
			t.Fatalf("MutateJson on comp failed: %v", err)
		}
	}

	n, err = getRandomIntUpToN(cons, 100)
	if err != nil {
		t.Fatalf("fuzzhdr consumer error: %v", err)
	}
	if n < swapProb {
		origBytes, compBytes = compBytes, origBytes
	}

	aStr := string(origBytes)
	bStr := string(compBytes)

	a, err := ReadJsonString(aStr)
	if err != nil || a == nil {
		t.Skipf("Invalid JSON A: %v (err: %v)", aStr, err)
		return
	}
	b, err := ReadJsonString(bStr)
	if err != nil || b == nil {
		t.Skipf("Invalid JSON B: %v (err: %v)", bStr, err)
		return
	}

	formats := [][2]string{
		{"jd", "list"},
		{"jd", "set"},
		{"jd", "mset"},
		{"jd", "color"},
		{"patch", "list"},
		{"merge", "list"},
	}

	for _, format := range formats {
		t.Run(format[0]+"_"+format[1], func(t *testing.T) {
			a, _ = ReadJsonString(aStr) // fresh parse
			if format[0] == "merge" {
				if hasUnsupportedNullValue(a) || hasUnsupportedNullValue(b) {
					t.Skip("Skipping merge test due to unsupported null value")
					return
				}
				if b.Equals(jsonObject{}) {
					t.Skip("Skipping merge test for empty object (noop)")
					return
				}
			}

			var options []Option
			switch format[0] {
			case "jd":
				switch format[1] {
				case "set":
					options = append(options, setOption{})
				case "mset":
					options = append(options, multisetOption{})
				case "color":
					options = append(options, COLOR)
				}
			case "merge":
				options = append(options, mergeOption{})
			}

			d := a.Diff(b, options...)
			if d == nil {
				t.Errorf("nil diff returned")
				return
			}
			if format[0] == "patch" && hasUnsupportedObjectKey(d) {
				t.Skip("Unsupported object key in patch format")
				return
			}

			var (
				diffStr string
				diffObj Diff
			)
			switch format[0] {
			case "jd":
				diffStr = d.Render(options...)
				if format[1] == "color" {
					diffStr = stripAnsiCodes(diffStr)
				}
				diffObj, err = ReadDiffString(diffStr)
			case "patch":
				diffStr, err = d.RenderPatch()
				if err != nil {
					t.Errorf("RenderPatch error: %v", err)
					return
				}
				diffObj, err = ReadPatchString(diffStr)
			case "merge":
				diffStr, err = d.RenderMerge()
				if err != nil {
					t.Errorf("RenderMerge error: %v", err)
					return
				}
				diffObj, err = ReadMergeString(diffStr)
			}
			if err != nil {
				t.Errorf("Failed to parse diff string (%s): %v", format[0], err)
				return
			}

			patchedA, err := a.Patch(diffObj)
			if err != nil {
				t.Errorf("Patch error (%s): %v", format[0], err)
				return
			}
			if !patchedA.Equals(b, options...) {
				t.Errorf("Patch mismatch (%s): got %v, want %v", format[0], renderJson(patchedA), bStr)
				return
			}
		})
	}
}
