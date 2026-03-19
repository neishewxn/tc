package http

import (
	"bufio"
	"net/http"
)

func ReadRequest(b *bufio.Reader) (req *http.Request, err error) {
	return http.ReadRequest(b)
}
