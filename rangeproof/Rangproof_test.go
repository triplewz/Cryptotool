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
	proof,err := NewProof(v,rng)
	if err != nil {
		t.Fatalf("产生证明过程错误！")
		return
	}

	//测试验证过程
	if !Verify(proof) {
		t.Fatalf("验证过程错误！")
		return
	}
}

func BenchmarkProof(b *testing.B) {
	rng, err := GetRand()
	if err != nil {
		b.Fatalf("随机数产生错误！")
		return
	}

	var v = 150

	//测试证明过程
	for i:=0;i<b.N;i++ {
		_,_ = NewProof(v,rng)
	}
}

func BenchmarkVerify(b *testing.B) {
	rng, err := GetRand()
	if err != nil {
		b.Fatalf("随机数产生错误！")
		return
	}

	var v = 150

	proof,_ := NewProof(v,rng)

	//测试证明过程
	for i:=0;i<b.N;i++ {
		_ = Verify(proof)
	}
}