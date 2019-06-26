package dkmixer

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"cryptogm/sm/sm4"
	"github.com/pkg/errors"
)

type TransAddr struct {
	TansPubKey    *SECP256K1.ECP
	OneTimeAddr   *SECP256K1.ECP
	CipherText    []byte
}

type RecevKey struct {
	AddrSk  *SECP256K1.BIG
	DecKey  []byte
}

//为接收方派生交易地址
func NewTansAddr(upk *UserPubKey,regPubKey *RegulatorPubKey, rng *amcl.RAND) (*TransAddr, error) {
	if upk == nil || regPubKey == nil || rng == nil {
		return nil, errors.Errorf("输入不能为空！")
	}

	transAddr := new(TransAddr)

	r := RandModOrder(rng)
	R := GenG1.Mul(r)

	rA := upk.PK1.Mul(r)
	data := make([]byte, 2*FieldBytes+1)
	rA.ToBytes(data[:],true)
	hashValue := HashModOrder(data)

	//交易地址
	P := GenG1.Mul(hashValue)
	P.Add(upk.PK2)

	//交易加密密钥
	//encKey1 := BigToBytes(hashValue)

	//辅助加密密钥
	K1 := regPubKey.RPK.Mul(r)
	encKeyData2 := make([]byte,2*FieldBytes+1)
	K1.ToBytes(encKeyData2,true)
	encKey2 := BigToBytes(HashModOrder(encKeyData2))

	//辅助信息加密，包括A，B，P，R
	encData := make([]byte,4*(2*FieldBytes+1))
	transAddr.CipherText = make([]byte,4*(2*FieldBytes+1))
	length := 2*FieldBytes+1
	index := 0
	upk.PK1.ToBytes(encData[index:length],true)
	upk.PK2.ToBytes(encData[length:2*length],true)
	P.ToBytes(encData[2*length:3*length],true)
	R.ToBytes(encData[3*length:4*length],true)

	//sm4加密
	transAddr.CipherText = sm4.Sm4Ecb(encKey2,encData,sm4.ENC)

	transAddr.TansPubKey = R
	transAddr.OneTimeAddr = P

	return transAddr,nil
}

//接收方交易私钥
func NewRecevKey(transAddr *TransAddr, usk *UserSKey) (*RecevKey, error) {
	if transAddr == nil || usk == nil {
		return nil, errors.Errorf("输入不能为空！")
	}

	recevKey := new(RecevKey)

	aR := transAddr.TansPubKey.Mul(usk.SK1)
	hashData := make([]byte,2*FieldBytes+1)
	aR.ToBytes(hashData[:],true)
	hashValue := HashModOrder(hashData)

	recevKey.AddrSk = Modadd(hashValue,usk.SK2,GroupOrder)
	recevKey.DecKey = BigToBytes(hashValue)

	return recevKey,nil
}

//验证接收密钥是否正确
func RecevKeyVer(transAddr *TransAddr,recevKey *RecevKey) error {
	if transAddr == nil || recevKey == nil{
		return errors.Errorf("输入不能为空！")
	}

	Pprime := GenG1.Mul(recevKey.AddrSk)

	if !transAddr.OneTimeAddr.Equals(Pprime) {
		return errors.Errorf("接收密钥不正确！")
	}

	return nil
}