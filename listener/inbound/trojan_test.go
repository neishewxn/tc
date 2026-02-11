package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

func testInboundTrojan(t *testing.T, inboundOptions inbound.TrojanOption, outboundOptions outbound.TrojanOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "trojan_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.TrojanUser{
		{Username: "test", Password: userUUID},
	}
	in, err := inbound.NewTrojan(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "trojan_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID

	out, err := outbound.NewTrojan(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	testSingMux(t, tunnel, out)
}

func testInboundTrojanTLS(t *testing.T, inboundOptions inbound.TrojanOption, outboundOptions outbound.TrojanOption) {
	testInboundTrojan(t, inboundOptions, outboundOptions)
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundTrojan(t, inboundOptions, outboundOptions)
	})
}

func TestInboundTrojan_TLS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss1(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		WsPath:      "/ws",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss2(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Reality(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
	}
	outboundOptions := outbound.TrojanOption{
		SNI: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
	}
	testInboundTrojan(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_TLS_TrojanSS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		SSOption: inbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		SSOpts: outbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss_TrojanSS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		SSOption: inbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
		WsPath: "/ws",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		SSOpts: outbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}
