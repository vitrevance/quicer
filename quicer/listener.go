package quicer

import (
	"errors"
	"net"
	"sync/atomic"
)

type PoolListener struct {
	conns chan net.Conn
}

func NewPoolListener() *PoolListener {
	return &PoolListener{
		conns: make(chan net.Conn, 100),
	}
}

var ErrClosed = errors.New("Listener is closed")

// Accept implements net.Listener.
func (p *PoolListener) Accept() (net.Conn, error) {
	conn, ok := <-p.conns
	if ok {
		return conn, nil
	} else {
		return nil, ErrClosed
	}
}

// Addr implements net.Listener.
func (p *PoolListener) Addr() net.Addr {
	return nil
}

// Close implements net.Listener.
func (p *PoolListener) Close() error {
	close(p.conns)
	return nil
}

func (p *PoolListener) Connect(conn net.Conn) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClosed
		}
	}()
	p.conns <- conn
	return
}

func (p *PoolListener) Listen(listener net.Listener) {
	go func() {
		defer recover()
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.conns <- conn
		}
	}()
}

var _ net.Listener = (*PoolListener)(nil)

type SingleConnectionListener struct {
	Conn      net.Conn
	isExpired atomic.Bool
}

// Accept implements net.Listener.
func (s *SingleConnectionListener) Accept() (net.Conn, error) {
	if !s.isExpired.Swap(true) {
		return s.Conn, nil
	}
	return nil, ErrClosed
}

// Addr implements net.Listener.
func (s *SingleConnectionListener) Addr() net.Addr {
	return s.Conn.LocalAddr()
}

// Close implements net.Listener.
func (s *SingleConnectionListener) Close() error {
	return nil
}

var _ net.Listener = (*SingleConnectionListener)(nil)
