package jd

import (
	"math/rand/v2"

	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func BuildJSON(cons *fuzzhdr.ConsumeFuzzer, maxDepth int) interface{} {
	return buildWithDepth(cons, GetRandomIntUpToN(cons, maxDepth+1))
}

func buildWithDepth(cons *fuzzhdr.ConsumeFuzzer, depth int) interface{} {
	if depth == 0 {
		if GetRandomIntUpToN(cons, 9) == 0 {
			switch GetRandomIntUpToN(cons, 8) {
			case 0:
				return GetRandomInt(cons)
			case 1:
				return GetRandomFloat32(cons)
			case 2:
				return GetRandomFloat64(cons)
			case 3:
				return GetRandomByte(cons)
			case 4:
				return GetRandomUint(cons)
			case 5:
				return GetRandomUint16(cons)
			case 6:
				return GetRandomUint32(cons)
			case 7:
				return GetRandomUint64(cons)
			}
		}
		return GetRandomStr(cons)
	}

	if GetRandomBool(cons) {
		arr := make([]interface{}, GetRandomIntUpToN(cons, 5))
		for i := range arr {
			arr[i] = buildWithDepth(cons, depth-1)
		}
		return arr
	} else {
		n := GetRandomIntUpToN(cons, 5)
		m := make(map[string]interface{}, n)
		for i := 0; i < n; i++ {
			key := GetRandomStr(cons)
			m[key] = buildWithDepth(cons, depth-1)
		}
		return m
	}
}

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

func GenerateOverlapJSON(orig interface{}, cons *fuzzhdr.ConsumeFuzzer, renameProb int, mutateProb int) interface{} {
	origDepth := computeDepth(orig)
	if GetRandomIntUpToN(cons, 100) < mutateProb {
		return buildWithDepth(cons, GetRandomIntUpToN(cons, origDepth+1))
	}

	switch v := orig.(type) {
	case map[string]interface{}:
		type entry struct {
			k string
			v interface{}
		}
		entries := make([]entry, 0, len(v))
		for k, ov := range v {
			entries = append(entries, entry{k, ov})
		}

		newSize := len(entries)
		if GetRandomIntUpToN(cons, 100) < mutateProb {
			newSize += GetRandomIntUpToN(cons, len(entries)+1) - GetRandomIntUpToN(cons, len(entries)+1)
		}
		newMap := make(map[string]interface{}, newSize)
		rand.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
		n := min(newSize, len(entries))
		for i := range n {
			key := entries[i].k
			if GetRandomIntUpToN(cons, 100) < renameProb {
				key = GetRandomStr(cons)
			}
			newMap[key] = GenerateOverlapJSON(entries[i].v, cons, renameProb, mutateProb)
		}
		for i := n; i < newSize; i++ {
			newMap[GetRandomStr(cons)] = BuildJSON(cons, origDepth-1)
		}
		return newMap

	case []interface{}:
		newSize := len(v)
		if GetRandomIntUpToN(cons, 100) < mutateProb {
			newSize += GetRandomIntUpToN(cons, len(v)+1) - GetRandomIntUpToN(cons, len(v)+1)
		}
		newArr := make([]interface{}, newSize)
		n := min(newSize, len(v))
		for i := range n {
			newArr[i] = GenerateOverlapJSON(v[i], cons, renameProb, mutateProb)
		}

		for i := n; i < newSize; i++ {
			newArr[i] = BuildJSON(cons, origDepth-1)
		}
		return newArr

	default:
		return orig
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
