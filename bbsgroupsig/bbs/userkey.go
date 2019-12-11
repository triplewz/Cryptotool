package bbsgroupsig

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"math/big"
)

type UserKey struct {
	UK1                  []byte
	UK2                  *bn256.G1
}

//用户注册，群主生成用户签名私钥
func Registration(gmsk *GroupMasterKey) (*UserKey,error){
	uk := new(UserKey)

	//生成用户私钥
	x,_ := rand.Int(rand.Reader,bn256.Order)
	sk := new(big.Int).SetBytes(gmsk.Sk)
	temp := new(big.Int).Add(sk,x)
	temp.ModInverse(temp,bn256.Order)

	//tempInvert := new(big.Int).ModInverse(temp,bn256.Order)
	Ax := new(bn256.G1).ScalarBaseMult(temp)

	uk.UK1 = x.Bytes()
	uk.UK2 = Ax

	return uk,nil
}