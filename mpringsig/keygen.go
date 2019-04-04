package mpringsig

import (
	"github.com/pkg/errors"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
)

type Big []byte

type ECP struct {
	X    []byte
	Y    []byte
}

type SignKey struct {
	SK   []Big
	PK   []*ECP
}

type RingPK struct {
	N    int
	M    int
	PK   [][]*ECP
}

//生成签名者密钥
func NewSignKey(round int, rng *amcl.RAND) (*SignKey,error) {
	if rng == nil{
		return nil,errors.Errorf("无法产生签名者的密钥")
	}
	signKey := new(SignKey)
	for i := 0; i < round; i++{
		r := RandModOrder(rng)
		signKey.SK = append(signKey.SK,BigToBytes(r))
		signKey.PK = append(signKey.PK,EcpToProto(GenG1.Mul(r)))
	}
	return signKey,nil
}

//生成环成员公钥
func NewPubKey(rng *amcl.RAND, round int, num int) (*RingPK,error) {
	if rng == nil || num <= 0 || round <= 0 {
		return nil, errors.Errorf("未形成环")
	}
	ringPK := new(RingPK)
	ringPK.N = round
	ringPK.M = num

	r := RandModOrder(rng)
	Gr := EcpToProto(GenG1.Mul(r))
	for i := 0; i < round; i++ {
		var pk []*ECP
		for j:= 0; j < num ; j++ {
			pk = append(pk,Gr)
		}
		ringPK.PK = append(ringPK.PK,pk)
	}
	return ringPK,nil
}

//签名公钥加入公钥环中
func NewSignPubKey(ringPK *RingPK,signKey *SignKey, startIndx int) (*RingPK,error){
	if ringPK == nil || startIndx < 0 || startIndx >= ringPK.M {
		return nil, errors.Errorf("输入为空或起始位置错误")
	}
	signPubKey := new(RingPK)
	signPubKey.N = ringPK.N
	signPubKey.M = ringPK.M + 1
	for i := 0; i < signPubKey.N ; i++ {
		var signpk []*ECP
		for j := 0; j < startIndx; j++{
			signpk = append(signpk, ringPK.PK[i][j])
		}

		//在j = startIndx处插入签名者的公钥
		signpk = append(signpk,signKey.PK[i])

		for j := startIndx + 1; j < signPubKey.M; j++{
			signpk = append(signpk,ringPK.PK[i][j-1])
		}

		signPubKey.PK = append(signPubKey.PK,signpk)

	}
	return signPubKey, nil
}