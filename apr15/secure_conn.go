package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

// protocolHandshake is the string used to identify the protocol we are
// trying to communicate with.
var protocolHandshake = []byte("whispering gophers 1")
var badHandshakeResponse = []byte("you shall not pass!")

// ErrBadHandshake is the error emitted when there is a handshake error
// on either side of a connection.
var ErrBadHandshake = errors.New("bad client/server handshake")

type secureConn struct {
	r io.Reader
	w io.Writer
	c net.Conn
}

func (c *secureConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *secureConn) Write(p []byte) (int, error) {
	return c.w.Write(p)
}

func (c *secureConn) Close() error {
	return c.c.Close()
}

// Dial generates a private/public key pair, connects to the server,
// perform the handshake and returns a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	clientPriv, serverPub, err := clientHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, ErrBadHandshake
	}

	c := &secureConn{
		r: NewSecureReader(conn, clientPriv, serverPub),
		w: NewSecureWriter(conn, clientPriv, serverPub),
		c: conn,
	}
	return c, nil
}

// Serve starts a secure echo server on the provided listener.
func Serve(l net.Listener) error {
	for {
		// server waiting for connection
		switch conn, err := l.Accept(); {
		case err == nil:
			go serve(conn)
		default:
			return err
		}
	}
}

func serve(conn net.Conn) {
	// perform handshake
	serverPriv, clientPub, err := serverHandshake(conn)
	if err != nil {
		conn.Write(badHandshakeResponse)
		conn.Close()
		return
	}

	c := secureConn{
		r: NewSecureReader(conn, serverPriv, clientPub),
		w: NewSecureWriter(conn, serverPriv, clientPub),
		c: conn,
	}

	var buf [MaxMsgLen]byte
	for {
		n, err := c.Read(buf[0:])
		if err != nil {
			break
		}
		n, err = c.Write(buf[:n])
		if err != nil {
			break
		}
	}
	c.Close()
}

// serverHandshake performs the protocol handshake server-side
func serverHandshake(c net.Conn) (*[32]byte, *[32]byte, error) {
	// client sends protocolHandshake
	clientHandshake := make([]byte, len(protocolHandshake))

	switch _, err := c.Read(clientHandshake); {
	case err == io.EOF, err == io.ErrUnexpectedEOF:
		// no data?
		return nil, nil, io.ErrUnexpectedEOF
	case err != nil:
		// something else happened
		return nil, nil, err
	default:
		if !bytes.Equal(protocolHandshake, clientHandshake) {
			return nil, nil, ErrBadHandshake
		}
	}

	// server generates public/private key pair, sends public to client
	serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	if _, err := writeFull(c, serverPub[:]); err != nil {
		return nil, nil, err
	}

	// client generates public/private key pair, sends public to server
	clientPub, err := receiveKey(c)
	if err != nil {
		return nil, nil, err
	}

	return serverPriv, clientPub, nil
}

// clientHandshake performs the protocol handshake client-side
func clientHandshake(c net.Conn) (*[32]byte, *[32]byte, error) {
	// client sends protocolHandshake
	if _, err := writeFull(c, protocolHandshake); err != nil {
		return nil, nil, err
	}

	// server generates public/private key pair, sends public to client
	serverPub, err := receiveKey(c)
	if err != nil {
		return nil, nil, err
	}

	// client generates public/private key pair, sends public to server
	clientPub, clientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	if _, err := writeFull(c, clientPub[:]); err != nil {
		return nil, nil, err
	}

	return clientPriv, serverPub, nil
}

// receiveKey receives one public or private key over the provider
// reader
func receiveKey(r io.Reader) (*[32]byte, error) {
	key := [32]byte{}
	switch _, err := io.ReadFull(r, key[:]); {
	case err == io.EOF, err == io.ErrUnexpectedEOF:
		// no data?
		return nil, io.ErrUnexpectedEOF
	case err != nil:
		// something else happened
		return nil, err
	}

	return &key, nil
}
