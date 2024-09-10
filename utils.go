package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func getIP(r *http.Request) string {
	// Check if the request was forwarded by a proxy (e.g. X-Forwarded-For header)
	// This is useful when behind a load balancer or reverse proxy
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-Ip")
	}
	if ip != "" {
		// In case of multiple IPs in the X-Forwarded-For header, take the first one
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	// Otherwise, extract the IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Println("Error parsing RemoteAddr:", err)
		return ""
	}
	return ip
}
