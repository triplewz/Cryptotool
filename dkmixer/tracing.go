package dkmxier

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/pkg/errors"
	"cryptogm/sm/sm4"
)

//监管方追踪算法
func Tracing(tk *TracingKey, regKey *RegulatorKey, transAddr *TransAddr) (*UserPubKey, error) {
	if tk == nil || regKey == nil || transAddr == nil {
		return nil, errors.Errorf("输入不能为空！")
	}

	upk := new(UserPubKey)
	K := transAddr.TansPubKey.Mul(regKey.RSK)

	//计算解密密钥
	hashData1 := make([]byte,2*FieldBytes+1)
	K.ToBytes(hashData1,true)
	hashValue1 := HashModOrder(hashData1)

	decKey := BigToBytes(hashValue1)

	//解密交易中的密文
	plain := make([]byte,4*(2*FieldBytes+1))
	plain = sm4.Sm4Ecb(decKey,transAddr.CipherText,sm4.DEC)

	//恢复出A,B,P,R
	index := 0
	length := 2*FieldBytes+1
	A := SECP256K1.ECP_fromBytes(plain[index:length])
	B := SECP256K1.ECP_fromBytes(plain[length:2*length])
	P := SECP256K1.ECP_fromBytes(plain[2*length:3*length])
	R := SECP256K1.ECP_fromBytes(plain[3*length:4*length])

	aR := R.Mul(tk.TSK)
	hashData2 := make([]byte,2*FieldBytes+1)
	aR.ToBytes(hashData2,true)
	hashValue2 := HashModOrder(hashData2)
	Pprime := GenG1.Mul(hashValue2)
	Pprime.Add(tk.TPK)

	if !P.Equals(Pprime) && !A.Equals(upk.PK1) && !B.Equals(upk.PK2) {
		return nil, errors.Errorf("追踪结果不正确！")
	}

	upk.PK1 = A
	upk.PK2 = B
	return upk, nil
}
