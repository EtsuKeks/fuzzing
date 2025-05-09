package jd

import (
	fuzzhdr "github.com/AdaLogics/go-fuzz-headers"
)

func BuildJSON(cons *fuzzhdr.ConsumeFuzzer, maxDepth int) (interface{}, error) {
	depth, err := getRandomIntUpToN(cons, maxDepth+1)
	if err != nil {
		return nil, err
	}
	return buildWithDepth(cons, depth)
}

func buildWithDepth(cons *fuzzhdr.ConsumeFuzzer, depth int) (interface{}, error) {
	if depth == 0 {
		choice, err := getRandomIntUpToN(cons, 9)
		if err != nil {
			return nil, err
		}
		if choice != 0 {
			t, err := getRandomIntUpToN(cons, 8)
			if err != nil {
				return nil, err
			}
			switch t {
			case 0:
				return cons.GetInt()
			case 1:
				return getFloat32(cons)
			case 2:
				return getFloat64(cons)
			case 3:
				return cons.GetByte()
			case 4:
				return cons.GetUint()
			case 5:
				return cons.GetUint16()
			case 6:
				return cons.GetUint32()
			case 7:
				return cons.GetUint64()
			}
		}
		return getString(cons, 100)
	}

	boolVal, err := cons.GetBool()
	if err != nil {
		return nil, err
	}

	if boolVal {
		arrLen, err := getRandomIntUpToN(cons, 5)
		if err != nil {
			return nil, err
		}
		arr := make([]interface{}, arrLen)
		for i := range arr {
			child, err := buildWithDepth(cons, depth-1)
			if err != nil {
				return nil, err
			}
			arr[i] = child
		}
		return arr, nil
	} else {
		n, err := getRandomIntUpToN(cons, 5)
		if err != nil {
			return nil, err
		}
		m := make(map[string]interface{}, n)
		for range n {
			key, err := getString(cons, 100)
			if err != nil {
				return nil, err
			}
			val, err := buildWithDepth(cons, depth-1)
			if err != nil {
				return nil, err
			}
			m[key] = val
		}
		return m, nil
	}
}
