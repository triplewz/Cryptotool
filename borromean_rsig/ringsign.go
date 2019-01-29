package borromean_rsig

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/pkg/errors"
	"strconv"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
)

type HashValue struct {
	E    [][]*FP256BN.BIG
}

type kValue struct {
	K    []*FP256BN.BIG
}

type Com struct {
	R   []*FP256BN.ECP
} 

type RingSig struct {
	N     int
	M     int
	E_0   []byte
	S     [][]Big
}

//计算哈希值e=H(M|G|i|j)
func BorromeanHash(m []byte, G1 *FP256BN.ECP, i int, j int) *FP256BN.BIG{
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
	var k_i *FP256BN.BIG
	var r *FP256BN.BIG
	var G1 *FP256BN.ECP
	var G1Prime *FP256BN.ECP

	//hashValue.E = make([][]*FP256BN.BIG,round)
	//k.K = make([]*FP256BN.BIG,round)
	//ringSig.S = make([][]Big,round)

	//首先利用随机数填充hashValue,k,ringSig.S
	rand := RandModOrder(rng)
	for i := 0; i < round; i++ {
		var fillValue1 []*FP256BN.BIG
		var fillValue2 []Big
		for j := 0; j < num; j++{
			fillValue1 = append(fillValue1,rand)
			fillValue2 = append(fillValue2,BigToBytes(rand))
		}
		hashValue.E = append(hashValue.E,fillValue1)
		k.K = append(k.K,rand)
		ringSig.S = append(ringSig.S,fillValue2)
	}

	//从开始位置签名，start → e_0
	for i := 0; i < round; i++{
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
		hashValue.E[i][0] = FP256BN.FromBytes(ringSig.E_0)
		for j := 0; j < startIndx; j++{
			r = RandModOrder(rng)
			G1Prime = GenG1.Mul(r)
			G1Prime.Sub(EcpFromProto(signPubKey.PK[i][j]).Mul(hashValue.E[i][j]))
			hashValue.E[i][j+1] = BorromeanHash(m,G1Prime,i,j)
			ringSig.S[i][j] = BigToBytes(r)
		}
		ringSig.S[i][startIndx] = BigToBytes(Modadd(k.K[i],FP256BN.Modmul(FP256BN.FromBytes(signKey.SK[i]),hashValue.E[i][startIndx],GroupOrder),GroupOrder))
	}

	return ringSig, nil
}