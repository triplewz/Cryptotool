/*
rangeproof参考文献：
http://fc17.ifca.ai/bitcoin/papers/bitcoin17-final41.pdf
 */

package rangeproof

import (
	"strconv"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

const Size  int= 32
const Base  int= 2

type ECP struct {
	X    []byte
	Y    []byte
}

type Big []byte

type kValue struct {
	K    []*FP256BN.BIG
}

type eValue struct {
	E    [][]*FP256BN.BIG
}

type Randm struct {
	Rand    []*FP256BN.BIG
}

type HashR struct {
	R    []*FP256BN.ECP
} 

type Proof struct {
	E_0    []byte
	Com    []*ECP
	S      []Big
	H      *ECP
}

//将v转化为长度为64位的二进制形式的string数组
func ValueToVector(value int) []string {
	var valueVector []string
	var valueTuple []string
	valueStr := strconv.FormatInt(int64(value),2)
	str := []byte(valueStr)
	for _, s := range str {
		valueTuple = append(valueTuple, string(s))
	}

	//若valueTuple长度小于64，则将其扩充为64位的string数组
	if len(valueVector) < Size {
		for i := 0; i < Size - len(valueTuple); i++ {
			valueVector = append(valueVector,"0")
		}
	}
	valueVector = append(valueVector,valueTuple...)
	return valueVector
}

//指数运算
func Pow(base int, exp int) int {
	res := base
	for i := 0; i < exp-1; i ++ {
		res *= base
	}
	return res
}

//计算j.m^i.H的值,其中j != 0
func J_mi_H(H *FP256BN.ECP,j int,m int,i int) *FP256BN.ECP {
	var EcpPoint = H
	temp1 := Pow(m,i)
	temp2 := temp1*j
	temp := FP256BN.NewBIGint(temp2)
	EcpPoint = H.Mul(temp)
	return EcpPoint
}

//产生关于值value的rangeproof
func NewProof(value int, rng *amcl.RAND) (*Proof,error){
	if value < 0 || value > Pow(2,32) {
		return nil,errors.Errorf("输入值超过证明范围！")
	}

	rangeProof := new(Proof)
	k := new(kValue)
	e := new(eValue)
	R := new(HashR)
	randm := new(Randm)

	//生成元H
	h := RandModOrder(rng)
	H := GenG1.Mul(h)
	rangeProof.H = EcpToProto(H)

	valueVector := ValueToVector(value)

	//填充e
	re := RandModOrder(rng)
	for i := 0; i < Size; i++ {
		var fillValue []*FP256BN.BIG
		for j := 0; j < Base; j++ {
			fillValue = append(fillValue,re)
		}
		e.E = append(e.E,fillValue)
	}

	//填充Com
	Comm := GenG1.Mul(re)
	for i := 0; i < Size; i++ {
		rangeProof.Com = append(rangeProof.Com,EcpToProto(Comm))
	}

	for i := 0; i < Size; i++ {
		//v_i=0，计算k_i0,R_i
		if valueVector[i] == "0" {
			k_i0 := RandModOrder(rng)
			R_i := GenG1.Mul(k_i0)
			k.K = append(k.K,k_i0)
			R.R = append(R.R,R_i)
			randm.Rand = append(randm.Rand,k_i0)
		}

		//v_i!=0,计算C_i,对于j∈{1,Size-1},计算e_ij,最后计算R_i(m-1)
		if valueVector[i] == "1" {
			//计算C_i = Com(v_i*m^i,r_i)=v_i*m^i·H+r_i·G
			r_i := RandModOrder(rng)
			randm.Rand = append(randm.Rand,r_i)
			C_i := GenG1.Mul(r_i)
			jmiH := J_mi_H(H,1,2,i)
			C_i.Add(jmiH)
			rangeProof.Com[i] = EcpToProto(C_i)

			//计算e_i1 = H(k_i·G)
			k_i := RandModOrder(rng)
			k.K = append(k.K,k_i)
			HashK_i := make([]byte,2*FieldBytes+1)
			index1 := 0
			index1 = appendBytesG1(HashK_i,index1,GenG1.Mul(k_i))
			e_i1 := HashModOrder(HashK_i)
			e.E[i][1] = e_i1

			//计算R_i(m-1) = e_i(m-1)·C_i
			R_i := C_i.Mul(e_i1)
			R.R = append(R.R,R_i)
		}
	}

	//计算e_0=H(R_0||R_1||...||R_n-1)
	HashData2 := make([]byte,Size*(2*FieldBytes+1))
	index2 := 0
	for i := 0; i < Size; i++ {
		index2 = appendBytesG1(HashData2,index2,R.R[i])
	}
	e_0 := HashModOrder(HashData2)
	rangeProof.E_0 = BigToBytes(e_0)

	//设置e.E[i][0] = e_0
	for i :=0; i < Size; i++ {
		e.E[i][0] = e_0
	}

	//对于i∈{0,n-1}，计算e,s
	for i := 0; i < Size; i++ {
		//v_i = 0,计算C_i=R_i/e_i1
		if valueVector[i] == "0" {
			k_ij := RandModOrder(rng)
			//计算e_i1=H(k_ij·G+e_ij-1*m^i*j·H)
			HashData3 := make([]byte,2*FieldBytes+1)
			Gk := GenG1.Mul(k_ij)
			jmiH := J_mi_H(H,1,2,i)
			e_H := jmiH.Mul(e.E[i][0])
			Gk.Add(e_H)
			index3 := 0
			index3 = appendBytesG1(HashData3,index3,Gk)
			e_i1 := HashModOrder(HashData3)
			e.E[i][1] = e_i1

			//计算C_i=R_i/e_i1
			inverE := e_i1
			inverE.Invmodp(GroupOrder)
			C_i := R.R[i].Mul(inverE)
			rangeProof.Com[i] = EcpToProto(C_i)

			//计算s_i1
			temp1 := FP256BN.Modmul(k.K[i],e.E[i][0],GroupOrder)
			temp2 := FP256BN.Modmul(temp1,inverE,GroupOrder)
			s_i1 := k_ij.Plus(temp2)
			rangeProof.S = append(rangeProof.S,BigToBytes(s_i1))
		}

		//v_i != 0,计算s
		if valueVector[i] == "1" {
			temp3 := FP256BN.Modmul(e.E[i][0],randm.Rand[i],GroupOrder)
			s_i1 := k.K[i].Plus(temp3)
			rangeProof.S = append(rangeProof.S,BigToBytes(s_i1))
		}
	}
	return rangeProof, nil
}