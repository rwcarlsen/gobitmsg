package payload

import (
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	addr := &AddressInfo{
		Time:     time.Now(),
		Stream:   1,
		Services: 1,
		Ip:       "127.0.0.1",
		Port:     19840,
	}
	ver := &Version{
		Services:  1,
		Timestamp: time.Now(),
		ToAddr:    addr,
		FromAddr:  addr,
		UserAgent: "Go bitmessage Daemon",
		Streams:   []int{1},
	}

	data, err := ver.Encode(1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VersionDecode(data)
	if err != nil {
		t.Fatal(err)
	}

	data, err = ver.Encode(2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VersionDecode(data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddressInfo(t *testing.T) {
	addr := &AddressInfo{
		Time:     time.Now(),
		Stream:   1,
		Services: 1,
		Ip:       "127.0.0.1",
		Port:     19840,
	}

	data := addr.p1_encode()
	p1_addressInfoDecode(data)

	data = addr.p2_encode()
	p2_addressInfoDecode(data)

	data = addr.p1_encodeShort()
	p1_addressInfoDecodeShort(data)

	data = addr.p2_encodeShort()
	p2_addressInfoDecodeShort(data)
}
