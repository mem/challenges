package main

import (
        "crypto/rand"
        "fmt"
        "io"
        "net"
        "testing"

        "golang.org/x/crypto/nacl/box"
)

func TestReadWriter(t *testing.T) {
        priv, pub, err := box.GenerateKey(rand.Reader)
        if err != nil {
                t.Fatal(err)
        }

        r, w := io.Pipe()
        secureR := NewSecureReader(r, priv, pub)
        secureW := NewSecureWriter(w, priv, pub)

        // Encrypt hello world
        go fmt.Fprintf(secureW, "hello world\n")

        // Decrypt message
        buf := make([]byte, 1024)
        n, err := secureR.Read(buf)
        if err != nil {
                t.Fatal(err)
        }
        // Make sure we have hello world back
        if res := string(buf[:n]); res != "hello world\n" {
                t.Fatalf("Unexpected result: %s != %s", res, "hello world")
        }

        // Make sure we are secure
        // Encrypt hello world
        go fmt.Fprintf(secureW, "hello world\n")

        // Read from the underlying transport instead of the decoder
        buf = make([]byte, 1024)
        n, err = r.Read(buf)
        if err != nil {
                t.Fatal(err)
        }

        // Make sure we dont' read the plain text message.
        if res := string(buf[:n]); res == "hello world\n" {
                t.Fatal("Unexpected result. The message is not encrypted.")
        }
}

func TestSecureEchoServer(t *testing.T) {
        // Create a random listener
        l, err := net.Listen("tcp", ":0")
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

        expected := "hello world\n"
        if _, err := fmt.Fprintf(conn, expected); err != nil {
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

func TestSecureServe(t *testing.T) {
        // Create a random listener
        l, err := net.Listen("tcp", ":0")
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
        unexpected := "hello world\n"
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

func TestSecureDial(t *testing.T) {
        // Create a random listener
        l, err := net.Listen("tcp", ":0")
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
                                c.Write([]byte("65537|83330641294328149214238194321849321843219483219483291483219438214129483219874\n"))
                                buf := make([]byte, 2048)
                                n, err := c.Read(buf)
                                if err != nil {
                                        t.Fatal(err)
                                }
                                if got := string(buf[:n]); got == "hello world\n" {
                                        t.Fatal("Unexpected result. Got raw data instead of serialized key")
                                }
                        }(conn)
                }
        }(l)

        conn, err := Dial(l.Addr().String())
        if err != nil {
                t.Fatal(err)
        }
        defer conn.Close()

        expected := "hello world\n"
        if _, err := fmt.Fprintf(conn, expected); err != nil {
                t.Fatal(err)
        }
}
