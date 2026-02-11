package sniffer

import "github.com/metacubex/mihomo/constant"

type Sniffer interface {
	SupportNetwork() constant.NetWork
	// SniffData must not change input bytes
	SniffData(bytes []byte) (string, error)
	Protocol() string
	SupportPort(port uint16) bool
}

type ReplaceDomain func(metadata *constant.Metadata, host string)

type MultiPacketSniffer interface {
	WrapperSender(packetSender constant.PacketSender, replaceDomain ReplaceDomain) constant.PacketSender
}

const (
	TLS Type = iota
	HTTP
)

var (
	List = []Type{TLS, HTTP}
)

type Type int

func (rt Type) String() string {
	switch rt {
	case TLS:
		return "TLS"
	case HTTP:
		return "HTTP"
	default:
		return "Unknown"
	}
}
