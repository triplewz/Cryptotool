/*
SPDX-License-Identifier: Apache-2.0
*/

package idemix

import "github.com/hyperledger/fabric-amcl/amcl/FP256BN"

//CA can reveal the user's secret key from a signature with its tracing key when disputes occur.
//The details are shown in BBS group signature scheme.

func Tracing(sig *Signature, tk *TracingKey) (*K,error) {
    k := new(K)
	T1 := EcpFromProto(sig.GetT1())
	T2 := EcpFromProto(sig.GetT2())
	T3 := EcpFromProto(sig.GetT3())
	tk1 := FP256BN.FromBytes(tk.TK1)
	tk2 := FP256BN.FromBytes(tk.TK2)

	//decryption: to reveal user's secret key and trace the user's identity
	t := T1.Mul2(tk1,T2,tk2)
	T3.Sub(t)
    k.Ax = EcpToProto(T3)
	return k,nil
}
