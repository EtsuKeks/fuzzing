package jd

import (
	"encoding/json"
	"testing"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzJdMy(f *testing.F) {
	f.Fuzz(fuzzMy)
}

func fuzzMy(t *testing.T, input []byte) {
	cons := fuzzhdr.NewConsumer(input)
	const (
		maxDepth       = 3
		renameProb     = 20
		mutateProb     = 30
		mutateJsonProb = 25
		swapProb       = 50
	)

	origVal := BuildJSON(cons, maxDepth)
	origBytes, err := json.Marshal(origVal)
	if err != nil {
		t.Errorf("nil parsed orig: %v", origVal)
	}

	compVal := GenerateOverlapJSON(origVal, cons, renameProb, mutateProb)
	compBytes, err := json.Marshal(compVal)
	if err != nil {
		t.Errorf("nil parsed orig: %v", compVal)
	}

	if GetRandomIntUpToN(cons, 100) < mutateJsonProb {
		origBytes = []byte(MutateJson(string(origBytes), cons))
	}
	if GetRandomIntUpToN(cons, 100) < mutateJsonProb {
		compBytes = []byte(MutateJson(string(compBytes), cons))
	}

	if GetRandomIntUpToN(cons, 100) < swapProb {
		origBytes, compBytes = compBytes, origBytes
	}

	aStr := string(origBytes)
	bStr := string(compBytes)
	// Only valid JSON input.
	a, err := ReadJsonString(aStr)
	if err != nil {
		return
	}
	if a == nil {
		t.Errorf("nil parsed input: %q", aStr)
		return
	}
	b, err := ReadJsonString(bStr)
	if err != nil {
		return
	}
	if b == nil {
		t.Errorf("nil parsed input: %q", bStr)
		return
	}
	for _, format := range [][2]string{{
		"jd", "list",
	}, {
		"jd", "set",
	}, {
		"jd", "mset",
	}, {
		"jd", "color",
	}, {
		"patch", "list",
	}, {
		"merge", "list",
	}} {
		t.Run(format[0]+"_"+format[1], func(t *testing.T) {
			a, _ = ReadJsonString(aStr) // Fresh parsed copy.
			if format[0] == "merge" {
				if hasUnsupportedNullValue(a) {
					return
				}
				if hasUnsupportedNullValue(b) {
					return
				}
				if b.Equals(jsonObject{}) {
					// An empty object is a JSON Merge patch noop
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
				default: // list
				}
			case "merge":
				options = append(options, mergeOption{})
			default: // patch
			}

			// Diff A and B.
			d := a.Diff(b, options...)
			if d == nil {
				t.Errorf("nil diff of a and b")
				return
			}
			if format[0] == "patch" && hasUnsupportedObjectKey(d) {
				return
			}
			var diffABStr string
			var diffAB Diff
			switch format[0] {
			case "jd":
				diffABStr = d.Render(options...)
				if format[1] == "color" {
					diffABStr = stripAnsiCodes(diffABStr)
				}
				diffAB, err = ReadDiffString(diffABStr)
			case "patch":
				diffABStr, err = d.RenderPatch()
				if err != nil {
					t.Errorf("could not render diff %v as patch: %v", d, err)
					return
				}
				diffAB, err = ReadPatchString(diffABStr)
			case "merge":
				diffABStr, err = d.RenderMerge()
				if err != nil {
					t.Errorf("could not render diff %v as merge: %v", d, err)
					return
				}
				diffAB, err = ReadMergeString(diffABStr)
			}
			if err != nil {
				t.Errorf("error parsing diff string %q: %v", diffABStr, err)
				return
			}
			// Apply diff to A to get B.
			patchedA, err := a.Patch(diffAB)
			if err != nil {
				t.Errorf("applying patch %v to %v should give %v. Got err: %v", diffABStr, aStr, bStr, err)
				return
			}
			if !patchedA.Equals(b, options...) {
				t.Errorf("applying patch %v to %v should give %v. Got: %v", diffABStr, aStr, bStr, renderJson(patchedA))
				return
			}
		})
	}

}
