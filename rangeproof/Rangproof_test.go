package rangeproof

import (
	"testing"
)

func TestRangeproof(t *testing.T){
	//测试随机数
	rng, err := GetRand()
	if err != nil {
		t.Fatalf("随机数产生错误！")
		return
	}

	var v = 150

	//测试证明过程
	proof, err := NewProof(v,rng)
	if err != nil {
		t.Fatalf("产生证明过程错误！")
		return
	}

	//测试验证过程
	err = Verify(proof)
	if err != nil {
		t.Fatalf("验证过程错误！")
		return
	}
}
