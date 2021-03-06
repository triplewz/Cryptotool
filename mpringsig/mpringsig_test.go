package mpringsig

import (
	"math/rand"
	"testing"
	"time"
)

func TestRingSig(t *testing.T) {
	//设置n=5个环，每个环有m=2个人（含签名者）,m至少为2.
	round := 5
	num := 2

	//签名消息为"Borromean ring signature"
	m := []byte("Borromean ring signature")

	rng,err := GetRand()
	if err != nil {
		t.Fatalf("随机数生成错误")
		return
	}

	//测试用户签名密钥
	signKey,err := NewSignKey(round,rng)
	if err != nil {
		t.Fatalf("签名密钥生成错误")
		return
	}

	//测试环公钥
	ringPK,err := NewPubKey(rng,round,num-1)
	if err != nil {
		t.Fatalf("环公钥生成错误")
		return
	}

	//确定签名起始位置
	rand.Seed(time.Now().UnixNano())
	startIndx := rand.Intn(num-1)

	//将签名者公钥插入环公钥
	signPubKey,err := NewSignPubKey(ringPK,signKey,startIndx)
	if err != nil {
		t.Fatalf("签名者公钥未正确加入环公钥")
		return
	}

	//测试环签名
	ringSig,err := NewRingSig(signPubKey,signKey,rng,m,round,num,startIndx)
	if err != nil {
		t.Fatalf("环签名生成错误")
		return
	}

	//测试验证过程，有效的环签名可通过验证
	if !RingSigVerfy(ringSig,signPubKey,m) {
		t.Fatalf("环签名验证无效")
		return
	}

	//输入错误信息，验证不通过
	if RingSigVerfy(ringSig,signPubKey,[]byte("dadaa")) {
		t.Fatalf("输入无效信息验证应不通过！！")
		return
	}
}

func BenchmarkRingSig(b *testing.B) {
	//设置n=5个环，每个环有m=2个人（含签名者）,m至少为2.
	round := 5
	num := 2

	//签名消息为"Borromean ring signature"
	m := []byte("Borromean ring signature")

	rng,err := GetRand()
	if err != nil {
		b.Fatalf("随机数生成错误")
		return
	}

	//测试用户签名密钥
	signKey,err := NewSignKey(round,rng)
	if err != nil {
		b.Fatalf("签名密钥生成错误")
		return
	}

	//测试环公钥
	ringPK,err := NewPubKey(rng,round,num-1)
	if err != nil {
		b.Fatalf("环公钥生成错误")
		return
	}

	//将签名者公钥插入环公钥
	signPubKey,err := NewSignPubKey(ringPK,signKey,0)
	if err != nil {
		b.Fatalf("签名者公钥未正确加入环公钥")
		return
	}

	for i:=0;i<b.N;i++ {
		_,_ = NewRingSig(signPubKey,signKey,rng,m,round,num,0)
	}
}

func BenchmarkRingSigVerfy(b *testing.B) {
	//设置n=5个环，每个环有m=2个人（含签名者）,m至少为2.
	round := 5
	num := 2

	//签名消息为"Borromean ring signature"
	m := []byte("Borromean ring signature")

	rng,err := GetRand()
	if err != nil {
		b.Fatalf("随机数生成错误")
		return
	}

	//测试用户签名密钥
	signKey,err := NewSignKey(round,rng)
	if err != nil {
		b.Fatalf("签名密钥生成错误")
		return
	}

	//测试环公钥
	ringPK,err := NewPubKey(rng,round,num-1)
	if err != nil {
		b.Fatalf("环公钥生成错误")
		return
	}

	//将签名者公钥插入环公钥
	signPubKey,err := NewSignPubKey(ringPK,signKey,0)
	if err != nil {
		b.Fatalf("签名者公钥未正确加入环公钥")
		return
	}

	//测试环签名
	ringSig,err := NewRingSig(signPubKey,signKey,rng,m,round,num,0)
	if err != nil {
		b.Fatalf("环签名生成错误")
		return
	}

	//测试验证过程，有效的环签名可通过验证
	if !RingSigVerfy(ringSig,signPubKey,m) {
		b.Fatalf("环签名验证无效")
		return
	}

	for i:=0;i<b.N;i++ {
		_ = RingSigVerfy(ringSig,signPubKey,[]byte("dadaa"))
	}
}