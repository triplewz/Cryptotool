/*
double key mixer (double key Mixer).
基于双密钥对派生的可监管隐身地址方案。
*/
package dkmixer

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/pkg/errors"
)

type UserKey struct {
	UPK   *UserPubKey
	USK   *UserSKey
}

type UserPubKey struct {
	PK1   *SECP256K1.ECP
	PK2   *SECP256K1.ECP
}

type UserSKey struct {
	SK1   *SECP256K1.BIG
	SK2   *SECP256K1.BIG
}

type TracingKey struct {
	TSK   *SECP256K1.BIG
	TPK   *SECP256K1.ECP
}

type RegulatorKey struct {
	RSK   *SECP256K1.BIG
	RPK   *RegulatorPubKey
}

type RegulatorPubKey struct {
	RPK   *SECP256K1.ECP
}


//产生用户原始密钥，包含两对密钥(a,A),(b,B)
func NewUserKey(rng *amcl.RAND) (*UserKey, error){
	if rng == nil {
		return nil, errors.Errorf("输入不能为空！")
	}
	uk := new(UserKey)
	upk := new(UserPubKey)
	usk := new(UserSKey)

	a := RandModOrder(rng)
	b := RandModOrder(rng)

	usk.SK1 = a
	usk.SK2 = b

	upk.PK1 = GenG1.Mul(a)
	upk.PK2 = GenG1.Mul(b)

	uk.UPK = upk
	uk.USK = usk

	return uk, nil
}

//产生追踪密钥(a,B)
func NewTracingKey(userKey *UserKey) (*TracingKey, error) {
	if userKey == nil {
		return nil, errors.Errorf("输入不能为空！")
	}

	tk := new(TracingKey)

	tk.TSK = userKey.USK.SK1
	tk.TPK = userKey.UPK.PK2

	return tk,nil
}

//产生监管者密钥对(sk,pk)
func NewRegulatorKey(rng *amcl.RAND) (*RegulatorKey,error){
	if rng == nil {
		return nil, errors.Errorf("输入不能为空！")
	}
	regKey := new(RegulatorKey)
	regPubKey := new(RegulatorPubKey)

	r := RandModOrder(rng)
	regKey.RSK = r
	regPubKey.RPK = GenG1.Mul(r)
	regKey.RPK = regPubKey

	return regKey,nil
}

