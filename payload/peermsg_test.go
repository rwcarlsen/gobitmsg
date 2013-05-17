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

	data := ver.Encode()
	_, err := VersionDecode(data)
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

	data := addr.encode()
	addressInfoDecode(data)

	data = addr.encodeShort()
	addressInfoDecodeShort(data)
}
