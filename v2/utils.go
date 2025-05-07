package jd

import fuzzhdr "github.com/AdaLogics/go-fuzz-headers"

func GetRandomBool(cons *fuzzhdr.ConsumeFuzzer) bool {
	out, _ := cons.GetBool()
	return out
}

func GetRandomInt(cons *fuzzhdr.ConsumeFuzzer) int {
	idx, _ := cons.GetInt()
	return idx
}

func GetRandomFloat32(cons *fuzzhdr.ConsumeFuzzer) float32 {
	out, _ := cons.GetFloat32()
	return out
}

func GetRandomFloat64(cons *fuzzhdr.ConsumeFuzzer) float64 {
	out, _ := cons.GetFloat64()
	return out
}

func GetRandomByte(cons *fuzzhdr.ConsumeFuzzer) byte {
	out, _ := cons.GetByte()
	return out
}

func GetRandomUint(cons *fuzzhdr.ConsumeFuzzer) uint {
	out, _ := cons.GetUint()
	return out
}

func GetRandomUint16(cons *fuzzhdr.ConsumeFuzzer) uint16 {
	out, _ := cons.GetUint16()
	return out
}

func GetRandomUint32(cons *fuzzhdr.ConsumeFuzzer) uint32 {
	out, _ := cons.GetUint32()
	return out
}

func GetRandomUint64(cons *fuzzhdr.ConsumeFuzzer) uint64 {
	out, _ := cons.GetUint64()
	return out
}

func GetRandomStr(cons *fuzzhdr.ConsumeFuzzer) string {
	out, _ := cons.GetString()
	return out
}

func GetRandomIntUpToN(cons *fuzzhdr.ConsumeFuzzer, num int) int {
	idx, _ := cons.GetInt()
	return (idx%num + num) % num
}
