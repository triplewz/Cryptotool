package bbsgroupsig

import "github.com/milagro-crypto/amcl/version3/go/amcl"

//生成群密钥，包括追踪密钥和群公钥
func NewGroupKey(rng *amcl.RAND) (*GroupKey,error){
	gk := new(GroupKey)

	//生成主密钥
	gama := RandModOrder(rng)
	W := GenG2.Mul(gama)

	gk.Gmsk = new(GroupMasterKey)

	gk.Gmsk.Sk = BigToBytes(gama)

	//生成追踪密钥
	r1 := RandModOrder(rng)
	r2 := RandModOrder(rng)

	gk.TK = new(TracingKey)

	gk.TK.TK1 = BigToBytes(r1)
	gk.TK.TK2 = BigToBytes(r2)

	//生成群公钥
	U := GenG1.Mul(r2)
	V := GenG1.Mul(r1)
	H := U.Mul(r1)

	gk.GPK = new(GroupPublicKey)

	gk.GPK.U = EcpToProto(U)
	gk.GPK.V = EcpToProto(V)
	gk.GPK.H = EcpToProto(H)
	gk.GPK.W = Ecp2ToProto(W)

	return gk,nil
}
