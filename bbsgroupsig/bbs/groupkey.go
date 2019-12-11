package bbsgroupsig

import (
	"github.com/cloudflare/bn256"
	"crypto/rand"
)

type GroupMasterKey struct {
	Sk      []byte
}

type TracingKey struct {
	TK1       []byte
	TK2       []byte
}

type GroupPublicKey struct {
	U        *bn256.G1
	V        *bn256.G1
	H        *bn256.G1
	W        *bn256.G2
}

type GroupKey struct {
	Gmsk       *GroupMasterKey
	TK         *TracingKey
	GPK        *GroupPublicKey
} 

//生成群密钥，包括追踪密钥和群公钥
func NewGroupKey() (*GroupKey,error){
	gk := new(GroupKey)

	//生成主密钥
	gama,_ := rand.Int(rand.Reader,bn256.Order)
	W := new(bn256.G2).ScalarBaseMult(gama)

	gk.Gmsk = new(GroupMasterKey)

	gk.Gmsk.Sk = gama.Bytes()

	//生成追踪密钥
	r1,_ := rand.Int(rand.Reader,bn256.Order)
	r2,_ := rand.Int(rand.Reader,bn256.Order)

	gk.TK = new(TracingKey)

	gk.TK.TK1 = r1.Bytes()
	gk.TK.TK2 = r2.Bytes()

	//生成群公钥
	U := new(bn256.G1).ScalarBaseMult(r2)
	V := new(bn256.G1).ScalarBaseMult(r1)
	H := new(bn256.G1).ScalarMult(U,r1)

	gk.GPK = new(GroupPublicKey)

	gk.GPK.U = U
	gk.GPK.V = V
	gk.GPK.H = H
	gk.GPK.W = W

	return gk,nil
}
