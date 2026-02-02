package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/kcptun"

	shadowsocks "github.com/metacubex/sing-shadowsocks2"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type ShadowSocks struct {
	*Base
	method shadowsocks.Method

	option       *ShadowSocksOption
	kcptunClient *kcptun.Client
}

type ShadowSocksOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Password          string         `proxy:"password"`
	Cipher            string         `proxy:"cipher"`
	UDP               bool           `proxy:"udp,omitempty"`
	Plugin            string         `proxy:"plugin,omitempty"`
	PluginOpts        map[string]any `proxy:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `proxy:"udp-over-tcp-version,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

type kcpTunOption struct {
	Key          string `obfs:"key,omitempty"`
	Crypt        string `obfs:"crypt,omitempty"`
	Mode         string `obfs:"mode,omitempty"`
	Conn         int    `obfs:"conn,omitempty"`
	AutoExpire   int    `obfs:"autoexpire,omitempty"`
	ScavengeTTL  int    `obfs:"scavengettl,omitempty"`
	MTU          int    `obfs:"mtu,omitempty"`
	RateLimit    int    `obfs:"ratelimit,omitempty"`
	SndWnd       int    `obfs:"sndwnd,omitempty"`
	RcvWnd       int    `obfs:"rcvwnd,omitempty"`
	DataShard    int    `obfs:"datashard,omitempty"`
	ParityShard  int    `obfs:"parityshard,omitempty"`
	DSCP         int    `obfs:"dscp,omitempty"`
	NoComp       bool   `obfs:"nocomp,omitempty"`
	AckNodelay   bool   `obfs:"acknodelay,omitempty"`
	NoDelay      int    `obfs:"nodelay,omitempty"`
	Interval     int    `obfs:"interval,omitempty"`
	Resend       int    `obfs:"resend,omitempty"`
	NoCongestion int    `obfs:"nc,omitempty"`
	SockBuf      int    `obfs:"sockbuf,omitempty"`
	SmuxVer      int    `obfs:"smuxver,omitempty"`
	SmuxBuf      int    `obfs:"smuxbuf,omitempty"`
	FrameSize    int    `obfs:"framesize,omitempty"`
	StreamBuf    int    `obfs:"streambuf,omitempty"`
	KeepAlive    int    `obfs:"keepalive,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (ss *ShadowSocks) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	useEarly := N.NeedHandshake(c)
	if !useEarly {
		if ctx.Done() != nil {
			done := N.SetupContextForConn(ctx, c)
			defer done(&err)
		}
	}
	if metadata.NetWork == C.UDP && ss.option.UDPOverTCP {
		uotDestination := uot.RequestDestination(uint8(ss.option.UDPOverTCPVersion))
		if useEarly {
			return ss.method.DialEarlyConn(c, uotDestination), nil
		} else {
			return ss.method.DialConn(c, uotDestination)
		}
	}
	if useEarly {
		return ss.method.DialEarlyConn(c, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)), nil
	} else {
		return ss.method.DialConn(c, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	}
}

// DialContext implements C.ProxyAdapter
func (ss *ShadowSocks) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var c net.Conn
	if ss.kcptunClient != nil {
		c, err = ss.kcptunClient.OpenStream(ctx, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			if err = ss.ResolveUDP(ctx, metadata); err != nil {
				return nil, nil, err
			}
			addr, err := resolveUDPAddr(ctx, "udp", ss.addr, ss.prefer)
			if err != nil {
				return nil, nil, err
			}

			pc, err := ss.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
			if err != nil {
				return nil, nil, err
			}

			return pc, addr, nil
		})
	} else {
		c, err = ss.dialer.DialContext(ctx, "tcp", ss.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConnContext(ctx, c, metadata)
	return NewConn(c, ss), err
}

// ListenPacketContext implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if ss.option.UDPOverTCP {
		tcpConn, err := ss.DialContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return ss.ListenPacketOnStreamConn(ctx, tcpConn, metadata)
	}
	if err := ss.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	addr, err := resolveUDPAddr(ctx, "udp", ss.addr, ss.prefer)
	if err != nil {
		return nil, err
	}

	pc, err := ss.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, err
	}
	pc = ss.method.DialPacketConn(bufio.NewBindPacketConn(pc, addr))
	return newPacketConn(pc, ss), nil
}

// ProxyInfo implements C.ProxyAdapter
func (ss *ShadowSocks) ProxyInfo() C.ProxyInfo {
	info := ss.Base.ProxyInfo()
	info.DialerProxy = ss.option.DialerProxy
	return info
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (ss *ShadowSocks) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if ss.option.UDPOverTCP {
		if err = ss.ResolveUDP(ctx, metadata); err != nil {
			return nil, err
		}
		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if ss.option.UDPOverTCPVersion == uot.LegacyVersion {
			return newPacketConn(N.NewThreadSafePacketConn(uot.NewConn(c, uot.Request{Destination: destination})), ss), nil
		} else {
			return newPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), ss), nil
		}
	}
	return nil, C.ErrNotSupport
}

// SupportUOT implements C.ProxyAdapter
func (ss *ShadowSocks) SupportUOT() bool {
	return ss.option.UDPOverTCP
}

func (ss *ShadowSocks) Close() error {
	if ss.kcptunClient != nil {
		return ss.kcptunClient.Close()
	}
	return nil
}

func NewShadowSocks(option ShadowSocksOption) (*ShadowSocks, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	method, err := shadowsocks.CreateMethod(option.Cipher, shadowsocks.MethodOptions{
		Password: option.Password,
		TimeFunc: ntp.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("ss %s cipher: %s initialize error: %w", addr, option.Cipher, err)
	}

	var kcptunClient *kcptun.Client

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	if option.Plugin == kcptun.Mode {
		kcptunOpt := &kcpTunOption{}
		if err := decoder.Decode(option.PluginOpts, kcptunOpt); err != nil {
			return nil, fmt.Errorf("ss %s initialize kcptun-plugin error: %w", addr, err)
		}

		kcptunClient = kcptun.NewClient(kcptun.Config{
			Key:          kcptunOpt.Key,
			Crypt:        kcptunOpt.Crypt,
			Mode:         kcptunOpt.Mode,
			Conn:         kcptunOpt.Conn,
			AutoExpire:   kcptunOpt.AutoExpire,
			ScavengeTTL:  kcptunOpt.ScavengeTTL,
			MTU:          kcptunOpt.MTU,
			RateLimit:    kcptunOpt.RateLimit,
			SndWnd:       kcptunOpt.SndWnd,
			RcvWnd:       kcptunOpt.RcvWnd,
			DataShard:    kcptunOpt.DataShard,
			ParityShard:  kcptunOpt.ParityShard,
			DSCP:         kcptunOpt.DSCP,
			NoComp:       kcptunOpt.NoComp,
			AckNodelay:   kcptunOpt.AckNodelay,
			NoDelay:      kcptunOpt.NoDelay,
			Interval:     kcptunOpt.Interval,
			Resend:       kcptunOpt.Resend,
			NoCongestion: kcptunOpt.NoCongestion,
			SockBuf:      kcptunOpt.SockBuf,
			SmuxVer:      kcptunOpt.SmuxVer,
			SmuxBuf:      kcptunOpt.SmuxBuf,
			FrameSize:    kcptunOpt.FrameSize,
			StreamBuf:    kcptunOpt.StreamBuf,
			KeepAlive:    kcptunOpt.KeepAlive,
		})
		option.UDPOverTCP = true // must open uot
	}
	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("ss %s unknown udp over tcp protocol version: %d", addr, option.UDPOverTCPVersion)
	}

	outbound := &ShadowSocks{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Shadowsocks,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		method: method,

		option:       &option,
		kcptunClient: kcptunClient,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
