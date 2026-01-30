package convert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// ConvertsV2Ray convert V2Ray subscribe proxies data to mihomo proxies config
func ConvertsV2Ray(buf []byte) ([]map[string]any, error) {
	data := DecodeBase64(buf)

	arr := strings.Split(string(data), "\n")

	proxies := make([]map[string]any, 0, len(arr))
	names := make(map[string]int, 200)

	for _, line := range arr {
		line = strings.TrimRight(line, " \r")
		if line == "" {
			continue
		}

		scheme, body, found := strings.Cut(line, "://")
		if !found {
			continue
		}

		scheme = strings.ToLower(scheme)
		switch scheme {
		case "vless":
			urlVLess, err := url.Parse(line)
			if err != nil {
				continue
			}
			if decodedHost, err := tryDecodeBase64([]byte(urlVLess.Host)); err == nil {
				urlVLess.Host = string(decodedHost)
			}
			query := urlVLess.Query()
			vless := make(map[string]any, 20)
			err = handleVShareLink(names, urlVLess, scheme, vless)
			if err != nil {
				log.Warnln("error:%s line:%s", err.Error(), line)
				continue
			}
			if flow := query.Get("flow"); flow != "" {
				vless["flow"] = strings.ToLower(flow)
			}
			if encryption := query.Get("encryption"); encryption != "" {
				vless["encryption"] = encryption
			}
			proxies = append(proxies, vless)

		case "vmess":
			// V2RayN-styled share link
			// https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
			dcBuf, err := tryDecodeBase64([]byte(body))
			if err != nil {
				// Xray VMessAEAD share link
				urlVMess, err := url.Parse(line)
				if err != nil {
					continue
				}
				query := urlVMess.Query()
				vmess := make(map[string]any, 20)
				err = handleVShareLink(names, urlVMess, scheme, vmess)
				if err != nil {
					log.Warnln("error:%s line:%s", err.Error(), line)
					continue
				}
				vmess["alterId"] = 0
				vmess["cipher"] = "auto"
				if encryption := query.Get("encryption"); encryption != "" {
					vmess["cipher"] = encryption
				}
				proxies = append(proxies, vmess)
				continue
			}

			jsonDc := json.NewDecoder(bytes.NewReader(dcBuf))
			values := make(map[string]any, 20)

			if jsonDc.Decode(&values) != nil {
				continue
			}
			tempName, ok := values["ps"].(string)
			if !ok {
				continue
			}
			name := uniqueName(names, tempName)
			vmess := make(map[string]any, 20)

			vmess["name"] = name
			vmess["type"] = scheme
			vmess["server"] = values["add"]
			vmess["port"] = values["port"]
			vmess["uuid"] = values["id"]
			if alterId, ok := values["aid"]; ok {
				vmess["alterId"] = alterId
			} else {
				vmess["alterId"] = 0
			}
			vmess["udp"] = true
			vmess["xudp"] = true
			vmess["tls"] = false
			vmess["skip-cert-verify"] = false

			vmess["cipher"] = "auto"
			if cipher, ok := values["scy"].(string); ok && cipher != "" {
				vmess["cipher"] = cipher
			}

			if sni, ok := values["sni"].(string); ok && sni != "" {
				vmess["servername"] = sni
			}

			network, ok := values["net"].(string)
			if ok {
				network = strings.ToLower(network)
				if values["type"] == "http" {
					network = "http"
				} else if network == "http" {
					network = "h2"
				}
				vmess["network"] = network
			}

			tls, ok := values["tls"].(string)
			if ok {
				tls = strings.ToLower(tls)
				if strings.HasSuffix(tls, "tls") {
					vmess["tls"] = true
				}
				if alpn, ok := values["alpn"].(string); ok {
					vmess["alpn"] = strings.Split(alpn, ",")
				}
			}

			switch network {
			case "http":
				headers := make(map[string]any)
				httpOpts := make(map[string]any)
				if host, ok := values["host"].(string); ok && host != "" {
					headers["Host"] = []string{host}
				}
				httpOpts["path"] = []string{"/"}
				if path, ok := values["path"].(string); ok && path != "" {
					httpOpts["path"] = []string{path}
				}
				httpOpts["headers"] = headers

				vmess["http-opts"] = httpOpts

			case "h2":
				headers := make(map[string]any)
				h2Opts := make(map[string]any)
				if host, ok := values["host"].(string); ok && host != "" {
					headers["Host"] = []string{host}
				}

				h2Opts["path"] = values["path"]
				h2Opts["headers"] = headers

				vmess["h2-opts"] = h2Opts

			case "ws", "httpupgrade":
				headers := make(map[string]any)
				wsOpts := make(map[string]any)
				wsOpts["path"] = "/"
				if host, ok := values["host"].(string); ok && host != "" {
					headers["Host"] = host
				}
				if path, ok := values["path"].(string); ok && path != "" {
					path := path
					pathURL, err := url.Parse(path)
					if err == nil {
						query := pathURL.Query()
						if earlyData := query.Get("ed"); earlyData != "" {
							med, err := strconv.Atoi(earlyData)
							if err == nil {
								switch network {
								case "ws":
									wsOpts["max-early-data"] = med
									wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
								case "httpupgrade":
									wsOpts["v2ray-http-upgrade-fast-open"] = true
								}
								query.Del("ed")
								pathURL.RawQuery = query.Encode()
								path = pathURL.String()
							}
						}
						if earlyDataHeader := query.Get("eh"); earlyDataHeader != "" {
							wsOpts["early-data-header-name"] = earlyDataHeader
						}
					}
					wsOpts["path"] = path
				}
				wsOpts["headers"] = headers
				vmess["ws-opts"] = wsOpts

			case "grpc":
				grpcOpts := make(map[string]any)
				grpcOpts["grpc-service-name"] = values["path"]
				vmess["grpc-opts"] = grpcOpts
			}

			proxies = append(proxies, vmess)

		case "ss":
			urlSS, err := url.Parse(line)
			if err != nil {
				continue
			}

			name := uniqueName(names, urlSS.Fragment)
			port := urlSS.Port()

			if port == "" {
				dcBuf, err := encRaw.DecodeString(urlSS.Host)
				if err != nil {
					continue
				}

				urlSS, err = url.Parse("ss://" + string(dcBuf))
				if err != nil {
					continue
				}
			}

			var (
				cipherRaw = urlSS.User.Username()
				cipher    string
				password  string
			)
			cipher = cipherRaw
			if password, found = urlSS.User.Password(); !found {
				dcBuf, err := base64.RawURLEncoding.DecodeString(cipherRaw)
				if err != nil {
					dcBuf, _ = enc.DecodeString(cipherRaw)
				}
				cipher, password, found = strings.Cut(string(dcBuf), ":")
				if !found {
					continue
				}
				err = VerifyMethod(cipher, password)
				if err != nil {
					dcBuf, _ = encRaw.DecodeString(cipherRaw)
					cipher, password, found = strings.Cut(string(dcBuf), ":")
				}
			}

			ss := make(map[string]any, 10)

			ss["name"] = name
			ss["type"] = scheme
			ss["server"] = urlSS.Hostname()
			ss["port"] = urlSS.Port()
			ss["cipher"] = cipher
			ss["password"] = password
			query := urlSS.Query()
			ss["udp"] = true
			if query.Get("udp-over-tcp") == "true" || query.Get("uot") == "1" {
				ss["udp-over-tcp"] = true
			}
			plugin := query.Get("plugin")
			if strings.Contains(plugin, ";") {
				pluginInfo, _ := url.ParseQuery("pluginName=" + strings.ReplaceAll(plugin, ";", "&"))
				pluginName := pluginInfo.Get("pluginName")
				if strings.Contains(pluginName, "obfs") {
					ss["plugin"] = "obfs"
					ss["plugin-opts"] = map[string]any{
						"mode": pluginInfo.Get("obfs"),
						"host": pluginInfo.Get("obfs-host"),
					}
				} else if strings.Contains(pluginName, "v2ray-plugin") {
					ss["plugin"] = "v2ray-plugin"
					ss["plugin-opts"] = map[string]any{
						"mode": pluginInfo.Get("mode"),
						"host": pluginInfo.Get("host"),
						"path": pluginInfo.Get("path"),
						"tls":  strings.Contains(plugin, "tls"),
					}
				}
			}

			proxies = append(proxies, ss)

		case "socks", "socks5", "socks5h", "http", "https":
			link, err := url.Parse(line)
			if err != nil {
				continue
			}
			server := link.Hostname()
			if server == "" {
				continue
			}
			portStr := link.Port()
			if portStr == "" {
				continue
			}
			remarks := link.Fragment
			if remarks == "" {
				remarks = fmt.Sprintf("%s:%s", server, portStr)
			}
			name := uniqueName(names, remarks)
			encodeStr := link.User.String()
			var username, password string
			if encodeStr != "" {
				decodeStr := string(DecodeBase64([]byte(encodeStr)))
				splitStr := strings.Split(decodeStr, ":")

				// todo: should use url.QueryUnescape ?
				username = splitStr[0]
				if len(splitStr) == 2 {
					password = splitStr[1]
				}
			}
			socks := make(map[string]any, 10)
			socks["name"] = name
			socks["type"] = func() string {
				switch scheme {
				case "socks", "socks5", "socks5h":
					return "socks5"
				case "http", "https":
					return "http"
				}
				return scheme
			}()
			socks["server"] = server
			socks["port"] = portStr
			socks["username"] = username
			socks["password"] = password
			socks["skip-cert-verify"] = true
			if scheme == "https" {
				socks["tls"] = true
			}

			proxies = append(proxies, socks)
		}
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("convert v2ray subscribe error: format invalid")
	}

	return proxies, nil
}

func uniqueName(names map[string]int, name string) string {
	if index, ok := names[name]; ok {
		index++
		names[name] = index
		name = fmt.Sprintf("%s-%02d", name, index)
	} else {
		index = 0
		names[name] = index
	}
	return name
}
