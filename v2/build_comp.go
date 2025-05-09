package jd

import (
	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func GenerateOverlapJSON(cons *fuzzhdr.ConsumeFuzzer, orig interface{}, renameProb int, mutateProb int) (interface{}, error) {
	origDepth := computeDepth(orig)
	chance, err := getRandomIntUpToN(cons, 100)
	if err != nil {
		return nil, err
	}
	if chance < mutateProb {
		newDepth, err := getRandomIntUpToN(cons, origDepth+1)
		if err != nil {
			return nil, err
		}
		return buildWithDepth(cons, newDepth)
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

		chance, err = getRandomIntUpToN(cons, 100)
		if err != nil {
			return nil, err
		}
		if chance < mutateProb {
			shuffle(cons, len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
		}

		newSize, n, err := getNewSizeAndN(cons, len(entries), mutateProb)
		if err != nil {
			return nil, err
		}
		newMap := make(map[string]interface{}, newSize)

		for i := range n {
			key := entries[i].k
			renameChance, err := getRandomIntUpToN(cons, 100)
			if err != nil {
				return nil, err
			}
			if renameChance < renameProb {
				key, err = getString(cons, 100)
				if err != nil {
					return nil, err
				}
			}
			val, err := GenerateOverlapJSON(cons, entries[i].v, renameProb, mutateProb)
			if err != nil {
				return nil, err
			}
			newMap[key] = val
		}

		for i := n; i < newSize; i++ {
			key, err := getString(cons, 100)
			if err != nil {
				return nil, err
			}
			val, err := BuildJSON(cons, origDepth-1)
			if err != nil {
				return nil, err
			}
			newMap[key] = val
		}
		return newMap, nil

	case []interface{}:
		chance, err = getRandomIntUpToN(cons, 100)
		if err != nil {
			return nil, err
		}
		if chance < mutateProb {
			shuffle(cons, len(v), func(i, j int) { v[i], v[j] = v[j], v[i] })
		}

		newSize, n, err := getNewSizeAndN(cons, len(v), mutateProb)
		if err != nil {
			return nil, err
		}
		newArr := make([]interface{}, newSize)

		for i := range n {
			val, err := GenerateOverlapJSON(cons, v[i], renameProb, mutateProb)
			if err != nil {
				return nil, err
			}
			newArr[i] = val
		}

		for i := n; i < newSize; i++ {
			val, err := BuildJSON(cons, origDepth-1)
			if err != nil {
				return nil, err
			}
			newArr[i] = val
		}
		return newArr, nil

	default:
		return orig, nil
	}
}

func getNewSizeAndN(cons *fuzzhdr.ConsumeFuzzer, lenEntries int, mutateProb int) (newSize, n int, err error) {
	newSize = lenEntries
	chance, err := getRandomIntUpToN(cons, 100)
	if err != nil {
		return
	}
	if chance < mutateProb {
		add, err1 := getRandomIntUpToN(cons, lenEntries+1)
		sub, err2 := getRandomIntUpToN(cons, lenEntries+1)
		if err1 != nil || err2 != nil {
			err = err1
			return
		}
		newSize += add - sub
	}

	n = min(newSize, lenEntries)
	chance, err = getRandomIntUpToN(cons, 100)
	if err != nil {
		return
	}
	if chance < mutateProb {
		takeN, err1 := getRandomIntUpToN(cons, 2*n+1)
		if err1 != nil {
			err = err1
			return
		}
		n = min(n, takeN)
	}
	return
}
