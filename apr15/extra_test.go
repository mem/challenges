package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

const testPlaintext = "hello world\n"

func makeTestKeys() (*[32]byte, *[32]byte) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func wrapTestReaderAndWriter(t *testing.T, r io.Reader, w io.Writer) (io.Reader, io.Writer, func(), func()) {
	readerPriv, readerPub := makeTestKeys()
	writerPriv, writerPub := makeTestKeys()

	secureR := NewSecureReader(r, readerPriv, writerPub)
	if secureR == nil {
		t.Fatalf("Failed to create a SecureReader")
	}
	secureW := NewSecureWriter(w, writerPriv, readerPub)
	if secureW == nil {
		t.Fatalf("Failed to create a SecureWriter")
	}
	rCloser := func() {
		if rc, ok := r.(io.ReadCloser); ok {
			rc.Close()
		}
	}
	wCloser := func() {
		if wc, ok := w.(io.WriteCloser); ok {
			wc.Close()
		}
	}
	return secureR, secureW, rCloser, wCloser
}

func makeTestReaderAndWriter(t *testing.T) (io.Reader, io.Writer, func(), func()) {
	r, w := io.Pipe()
	return wrapTestReaderAndWriter(t, r, w)
}

func TestMoreReadWriterPing(t *testing.T) {
	r, w, rCloser, wCloser := makeTestReaderAndWriter(t)
	defer rCloser()

	// Encrypt hello world
	go func() {
		fmt.Fprintf(w, testPlaintext)
		wCloser()
	}()

	// Decrypt message
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]

	// Make sure we have hello world back
	if res := string(buf); res != testPlaintext {
		t.Fatalf("Unexpected result: %s != %s", res, "hello world")
	}
}

func TestMoreWriteClosedReader(t *testing.T) {
	_, w, rCloser, wCloser := makeTestReaderAndWriter(t)
	rCloser()
	defer wCloser()

	n, err := w.Write([]byte(testPlaintext))
	if n != 0 || err == nil {
		t.Fatal("Unexpected result. Writer should not be able to write.")
	}
}

func TestMoreWriteClosedWriter(t *testing.T) {
	_, w, rCloser, wCloser := makeTestReaderAndWriter(t)
	defer rCloser()
	wCloser()

	n, err := w.Write([]byte(testPlaintext))
	if n != 0 || err == nil {
		t.Fatal("Unexpected result. Writer should not be able to write.")
	}
}

func TestMoreReadClosedReader(t *testing.T) {
	r, _, rCloser, wCloser := makeTestReaderAndWriter(t)
	rCloser()
	defer wCloser()

	_, err := ioutil.ReadAll(r)
	if err == nil {
		t.Fatal("Unexpected result. Reader should not be able to read.")
	}
}

func TestMoreReadClosedWriter(t *testing.T) {
	r, _, rCloser, wCloser := makeTestReaderAndWriter(t)
	defer rCloser()
	wCloser()

	buf, err := ioutil.ReadAll(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatal("Unexpected result. Reader should report io.ErrUnexpectedEOF.")
	}
	if len(buf) != 0 {
		t.Fatal("Unexpected result. Buffer should be empty.")
	}
}

func TestMoreShortMessageRead(t *testing.T) {
	r, w := io.Pipe()

	secureR, secureW, rCloser, wCloser := wrapTestReaderAndWriter(t, r, w)
	defer rCloser()
	defer wCloser()

	// Write a full message
	go secureW.Write([]byte(testPlaintext))

	// steal the header + cypher text from the SecureReader
	// XXX: We are abusing knowledge of the internal implementation.
	// We know that since the underlyig io.Pipe writes entire
	// messages, two Read's are necessary.
	s := 0
	msg := make([]byte, 1024)

	n, _ := r.Read(msg[s:])
	s += n

	h := s // this is the header size

	n, _ = r.Read(msg[s:])
	s += n // this is the total message size

	// Write a short message
	go func() {
		w.Write(msg[:(h+s)/2])
		// the close is necessary for the SecureReader's
		// underlying ReadFull to stop trying to read the full
		// message.
		w.Close()
	}()

	// Read the short message using the SecureReader
	buf := make([]byte, h+s)
	if _, err := secureR.Read(buf); err != io.ErrUnexpectedEOF {
		t.Fatalf("Unexpected result: expecting io.ErrUnexpectedEOF, got %v.", err)
	}
}

func TestMoreShortHeaderRead(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))

	secureR, secureW, _, _ := wrapTestReaderAndWriter(t, buf, buf)

	// Write a full message
	secureW.Write([]byte(testPlaintext))

	// keep the header + cyphertext
	msg := make([]byte, buf.Len())
	buf.Read(msg)

	// Write back a short message with a truncated header
	buf.Write(msg[:4+8])

	// Read the short message
	if _, err := secureR.Read(msg); err != io.ErrUnexpectedEOF {
		t.Fatalf("Unexpected result: expecting io.ErrUnexpectedEOF, got %v.", err)
	}
}

func TestMoreReaderDecryptionError(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))

	secureR, secureW, _, _ := wrapTestReaderAndWriter(t, buf, buf)

	// Write a full message
	secureW.Write([]byte(testPlaintext))

	// keep the header + cypher text
	msg := make([]byte, buf.Len())
	buf.Read(msg)

	// corrupt cyphertext
	i := (headerLen + len(msg)) / 2
	msg[i] = ^msg[i]

	// Write back corrupted message
	buf.Write(msg)

	// Read the corrupted message
	if _, err := secureR.Read(msg); err != ErrDecryptionError {
		t.Fatalf("Unexpected result: expecting ErrDecryptionError, got %v.", err)
	}
}

func TestMoreSecureWriter(t *testing.T) {
	priv, pub := makeTestKeys()

	r, w := io.Pipe()
	secureW := NewSecureWriter(w, priv, pub)
	if secureW == nil {
		t.Fatalf("Failed to create a SecureWriter")
	}

	// Make sure we are secure
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, testPlaintext)
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if res := string(buf); res == testPlaintext {
		t.Fatal("Unexpected result. The message is not encrypted.")
	}

	r, w = io.Pipe()
	secureW = NewSecureWriter(w, priv, pub)
	if secureW == nil {
		t.Fatalf("Failed to create a SecureWriter")
	}

	// Make sure we are unique
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, testPlaintext)
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf2, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if string(buf) == string(buf2) {
		t.Fatal("Unexpected result. The encrypted message is not unique.")
	}
}

func TestMoreSecureEchoServer(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := testPlaintext
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		log.Println("Client failed while sending greeting to server")
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(buf[:n]); got != expected {
		t.Fatalf("Unexpected result:\nGot:\t\t%s\nExpected:\t%s\n", got, expected)
	}
}

func TestMoreSecureServe(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	unexpected := testPlaintext
	if _, err := fmt.Fprintf(conn, unexpected); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got == unexpected {
		t.Fatalf("Unexpected result:\nGot raw data instead of serialized key")
	}
}

func TestMoreSecureDial(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var key [32]byte
				c.Write(key[:])
				buf := make([]byte, 2048)
				n, err := c.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if got := string(buf[:n]); got == testPlaintext {
					t.Fatal("Unexpected result. Got raw data instead of encrypted")
				}
			}(conn)
		}
	}(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := testPlaintext
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		t.Fatal(err)
	}
}

func TestMoreShortMessage(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0, MsgOverhead))

	secureR, secureW, _, _ := wrapTestReaderAndWriter(t, buf, buf)

	// Write a short message
	if n, err := secureW.Write([]byte{}); err != nil {
		t.Fatalf("Unexpected result: expecting no error, got %v.", err)
	} else if n != 0 {
		t.Fatalf("Unexpected result: expecting 0 bytes written, got %d.", n)
	}

	msg := make([]byte, MsgOverhead)

	// Read the short message
	if n, err := secureR.Read(msg); err != nil {
		t.Fatalf("Unexpected result: expecting no error, got %v.", err)
	} else if n != 0 {
		t.Fatalf("Unexpected result: expecting 0 bytes read, got %d.", n)
	}
}

func TestMoreLongMessage(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0))

	secureR, secureW, _, _ := wrapTestReaderAndWriter(t, buf, buf)

	msg := make([]byte, MaxMsgLen)

	// Write a long message
	if n, err := secureW.Write(msg); err != nil {
		t.Fatalf("Unexpected result: expecting no error, got %v.", err)
	} else if n != len(msg) {
		t.Fatalf("Unexpected result: expecting len(msg) bytes written, got %d.", n)
	}

	// Read the long message
	if n, err := secureR.Read(msg); err != nil {
		t.Fatalf("Unexpected result: expecting no error, got %q.", err)
	} else if n != len(msg) {
		t.Fatalf("Unexpected result: expecting MaxMsgLen bytes read, got %d.", n)
	}
}

func TestMoreHugeMessage(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0))

	_, secureW, _, _ := wrapTestReaderAndWriter(t, buf, buf)

	msg := make([]byte, MaxMsgLen+1024)

	// Write a long message
	if n, err := secureW.Write(msg); err == nil {
		t.Fatalf("Unexpected result: expecting error, got %v.", err)
	} else if n != 0 {
		t.Fatalf("Unexpected result: no bytes should have been written, got %d.", n)
	}
}
