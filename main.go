package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
)

type ProxyServer struct {
	blockedDomains []string
}

func main() {
	proxy := &ProxyServer{}
	proxy.loadBlockedDomains("blacklist.txt")
	proxy.start("127.0.0.1:8080")
}

func (p *ProxyServer) loadBlockedDomains(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening blacklist:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		p.blockedDomains = append(p.blockedDomains, scanner.Text())
	}
}

func (p *ProxyServer) start(address string) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Listen error:", err)
		return
	}
	defer ln.Close()
	fmt.Println("Proxy listening on", address)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return
	}
	method := parts[0]
	address := parts[1]

	var host, port string
	if strings.Contains(address, ":") {
		split := strings.Split(address, ":")
		host, port = split[0], split[1]
	} else {
		host = address
		port = "80"
	}

	serverConn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		return
	}
	defer serverConn.Close()

	if method == "CONNECT" {
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		if err := p.fragmentData(clientConn, serverConn); err != nil {
			return
		}

		go io.Copy(serverConn, clientConn)
		io.Copy(clientConn, serverConn)
	} else {
		serverConn.Write([]byte(line))
		io.Copy(serverConn, reader)
		go io.Copy(serverConn, clientConn)
		io.Copy(clientConn, serverConn)
	}
}

func (p *ProxyServer) fragmentData(clientConn net.Conn, serverConn net.Conn) error {
	head := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, head); err != nil {
		return err
	}

	body := make([]byte, 2048)
	n, err := clientConn.Read(body)
	if err != nil && err != io.EOF {
		return err
	}
	body = body[:n]

	blocked := false
	for _, domain := range p.blockedDomains {
		if bytes.Contains(body, []byte(domain)) {
			blocked = true
			break
		}
	}
	if !blocked {
		_, err := serverConn.Write(append(head, body...))
		return err
	}

	var fragments [][]byte
	hostEnd := bytes.IndexByte(body, 0x00)
	if hostEnd != -1 {
		// первая часть до \x00
		first := make([]byte, 0)
		first = append(first, 0x16, 0x03, byte(rand.Intn(256))) // TLS header
		first = append(first, uint16ToBytes(uint16(hostEnd+1))...)
		first = append(first, body[:hostEnd+1]...)
		fragments = append(fragments, first)
		body = body[hostEnd+1:]
	}

	// фрагментируем остальное случайными блоками
	for len(body) > 0 {
		chunkLen := rand.Intn(len(body)) + 1
		if chunkLen > len(body) {
			chunkLen = len(body)
		}
		part := make([]byte, 0)
		part = append(part, 0x16, 0x03, byte(rand.Intn(256)))
		part = append(part, uint16ToBytes(uint16(chunkLen))...)
		part = append(part, body[:chunkLen]...)
		fragments = append(fragments, part)
		body = body[chunkLen:]
	}

	// отправляем все фрагменты
	for _, frag := range fragments {
		if _, err := serverConn.Write(frag); err != nil {
			return err
		}
	}

	return nil
}

func uint16ToBytes(n uint16) []byte {
	return []byte{byte(n >> 8), byte(n & 0xff)}
}
