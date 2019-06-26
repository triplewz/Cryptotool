package dkmixer

import (
	"testing"
)

func TestDKMixer(t *testing.T) {
	rng,err := GetRand()
	if err != nil {
		t.Fatalf("随机数生成错误！: \"%s\"", err)
		return
	}

	//测试用户密钥生成
	userKey,err := NewUserKey(rng)
	if err != nil {
		t.Fatalf("用户密钥生成错误: \"%s\"", err)
		return
	}

	//测试追踪密钥生成
	tracingKey,err := NewTracingKey(userKey)
	if err != nil {
		t.Fatalf("用户追踪密钥生成错误: \"%s\"", err)
		return
	}

	//测试监管者密钥生成
	regKey,err := NewRegulatorKey(rng)
	if err != nil {
		t.Fatalf("监管密钥生成错误: \"%s\"", err)
		return
	}

	//测试隐身地址派生
	transAddr,err := NewTansAddr(userKey.UPK,regKey.RPK,rng)
	if err != nil {
		t.Fatalf("交易地址生成错误: \"%s\"", err)
		return
	}

	//测试接收密钥过程
	recevKey,err := NewRecevKey(transAddr,userKey.USK)
	if err != nil {
		t.Fatalf("接收密钥生成错误！: \"%s\"", err)
		return
	}

	//测试接收密钥验证过程
	err = RecevKeyVer(transAddr,recevKey)
	if err != nil {
		t.Fatalf("接收密钥无效！: \"%s\"", err)
		return
	}

    //测试追踪过程
	tracKey,err := Tracing(tracingKey,regKey,transAddr)
	if err != nil {
		t.Fatalf("追踪过程错误！: \"%s\"", err)
		return
	}

	if !tracKey.PK1.Equals(userKey.UPK.PK1) && !tracKey.PK2.Equals(userKey.UPK.PK2) {
		t.Fatalf("追踪结果不正确！")
	}

}
