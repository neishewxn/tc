package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/tls"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	FingerPrint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	NextProtos        []string
	Reality           *tlsC.RealityConfig
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
		},
		Fingerprint: cfg.FingerPrint,
		Certificate: cfg.Certificate,
		PrivateKey:  cfg.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConn := tlsC.UClient(conn, tlsC.UConfig(tlsConfig), clientFingerprint)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
