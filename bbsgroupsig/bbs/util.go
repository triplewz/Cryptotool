package bbsgroupsig

import (
	"math/big"
	"github.com/cloudflare/bn256"
	"cryptogm/sm/sm3"
)

//hash a byte array to a big int.
func HashModOrder(data []byte) *big.Int {
	h := sm3.SumSM3(data)
	bigNum := new(big.Int).SetBytes(h[:])
	bigNum.Mod(bigNum,bn256.Order)
	return bigNum
}