package mpringsig

import (
	"github.com/pkg/errors"
	"strconv"
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
)

type HashValue struct {
	E    [][]*SECP256K1.BIG
}

type kValue struct {
	K    []*SECP256K1.BIG
}

type Com struct {
	R   []*SECP256K1.ECP
} 

type RingSig struct {
	N     int
	M     int
	E_0   []byte
	S     [][]Big
}

//计算哈希值e=H(M|G|i|j)
func BorromeanHash(m []byte, G1 *SECP256K1.ECP, i int, j int) *SECP256K1.BIG{
	hashData := make([]byte,len(m)+2*FieldBytes+1+len(strconv.Itoa(i))+len(strconv.Itoa(j)))
	index := 0
	index = appendBytesG1(hashData,index,G1)
	copy(hashData[index:],m)
	index = index + len(m)
	copy(hashData[index:],strconv.Itoa(i))
	index = index + len(strconv.Itoa(i))
	copy(hashData[index:],strconv.Itoa(j))
	h := HashModOrder(hashData)
	return h
}

//产生环签名
func NewRingSig(signPubKey *RingPK,signKey *SignKey, rng *amcl.RAND,m []byte, round int,num int, startIndx int) (*RingSig,error) {
	if rng == nil || round <= 0 || num <= 0 {
		return nil, errors.Errorf("输入有误，无法生成签名")
	}

	ringSig := new(RingSig)
	hashValue := new(HashValue)
	k := new(kValue)
	com := new(Com)

	//确定环个数和每个环成员个数(包括签名者)
	ringSig.N = round
	ringSig.M = num

	//签名
	var k_i *SECP256K1.BIG
	var r *SECP256K1.BIG
	var G1 *SECP256K1.ECP
	var G1Prime *SECP256K1.ECP

	hashValue.E = make([][]*SECP256K1.BIG,round)
	k.K = make([]*SECP256K1.BIG,round)
	ringSig.S = make([][]Big,round)

	//从开始位置签名，start → e_0
	for i := 0; i < round; i++{
		hashValue.E[i] = make([]*SECP256K1.BIG,num)
		ringSig.S[i] = make([]Big,num)
		k_i = RandModOrder(rng)
		G1 = GenG1.Mul(k_i)
		hashValue.E[i][startIndx+1] = BorromeanHash(m,G1,i,startIndx)
		k.K[i] = k_i
		for j := startIndx + 1; j < num - 1; j++ {
			r = RandModOrder(rng)
			G1Prime = GenG1.Mul(r)
			G1Prime.Sub(EcpFromProto(signPubKey.PK[i][j]).Mul(hashValue.E[i][j]))
			hashValue.E[i][j+1] = BorromeanHash(m,G1Prime,i,j)
			ringSig.S[i][j] = BigToBytes(r)
		}
		r = RandModOrder(rng)
		G1Prime = GenG1.Mul(r)
		G1Prime.Sub(EcpFromProto(signPubKey.PK[i][num-1]).Mul(hashValue.E[i][num-1]))
		ringSig.S[i][num-1] = BigToBytes(r)
		com.R = append(com.R,G1Prime)
	}

	//计算E_0
	HashE := make([]byte,round*(2*FieldBytes+1))
	index := 0
	for i := 0; i < round; i++ {
		index = appendBytesG1(HashE,index,com.R[i])
	}
	ringSig.E_0 = BigToBytes(HashModOrder(HashE))

	//签名闭环，从e_0到签名起始位置，e_0 → start
	for i := 0; i < round; i++ {
		hashValue.E[i][0] = SECP256K1.FromBytes(ringSig.E_0)
		for j := 0; j < startIndx; j++{
			r = RandModOrder(rng)
			G1Prime = GenG1.Mul(r)
			G1Prime.Sub(EcpFromProto(signPubKey.PK[i][j]).Mul(hashValue.E[i][j]))
			hashValue.E[i][j+1] = BorromeanHash(m,G1Prime,i,j)
			ringSig.S[i][j] = BigToBytes(r)
		}
		ringSig.S[i][startIndx] = BigToBytes(Modadd(k.K[i],SECP256K1.Modmul(SECP256K1.FromBytes(signKey.SK[i]),hashValue.E[i][startIndx],GroupOrder),GroupOrder))
	}

	return ringSig, nil
}