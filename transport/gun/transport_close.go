package gun

import (
	"golang.org/x/net/http2"
)

func closeTransport(tr *http2.Transport) {
	if tr != nil {
		tr.CloseIdleConnections()
	}
}
