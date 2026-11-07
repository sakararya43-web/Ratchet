// Package faultproxy interrupts only a test's real TCP connections. It does not
// emulate the database, broker or their acknowledgements.
package faultproxy

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type Proxy struct {
	listener    net.Listener
	target      string
	mu          sync.Mutex
	blocked     bool
	connections map[net.Conn]bool
	done        chan struct{}
	workers     sync.WaitGroup
}

func Start(t *testing.T, target string) *Proxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{listener: l, target: target, connections: map[net.Conn]bool{}, done: make(chan struct{})}
	go p.accept()
	t.Cleanup(func() { _ = l.Close(); p.Cut(); <-p.done; p.workers.Wait() })
	return p
}
func (p *Proxy) Address() string { return p.listener.Addr().String() }
func (p *Proxy) Cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked = true
	for c := range p.connections {
		_ = c.Close()
	}
}
func (p *Proxy) Heal() { p.mu.Lock(); p.blocked = false; p.mu.Unlock() }
func (p *Proxy) accept() {
	defer close(p.done)
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		blocked := p.blocked
		p.mu.Unlock()
		if blocked {
			_ = c.Close()
			continue
		}
		d, err := net.DialTimeout("tcp", p.target, time.Second)
		if err != nil {
			_ = c.Close()
			continue
		}
		p.mu.Lock()
		if p.blocked {
			p.mu.Unlock()
			_ = c.Close()
			_ = d.Close()
			continue
		}
		p.connections[c], p.connections[d] = true, true
		p.mu.Unlock()
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			copied := make(chan struct{})
			go func() { _, _ = io.Copy(d, c); _ = d.Close(); close(copied) }()
			_, _ = io.Copy(c, d)
			_ = c.Close()
			<-copied
			p.mu.Lock()
			delete(p.connections, c)
			delete(p.connections, d)
			p.mu.Unlock()
		}()
	}
}
