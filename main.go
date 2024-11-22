package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
)

const (
	guid           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC 6455 GUID
	textFrameByte  = 0x81
	closeFrameByte = 0x88
)

// 0x81 -> 1000 0001 first bit (1) indicates that if it's the last frame of the message (FIN=1)
// 000 -> reserved bits
// 0001 -> opcode

// OPCODES
// 0x1: text -> 0001
// 0x2: binary -> 0002
// 0x8: close -> 0008
// 0x9: ping -> 0009
// 0xA: pong -> 000A

func unmaskPayload(length int, reader *bufio.Reader) ([]byte, error) {
	mask := make([]byte, 4) // bytes 3, 4, 5 and 6 from ws frame
	_, err := reader.Read(mask)
	if err != nil {
		return nil, fmt.Errorf("error reading the mask %w", err)
	}

	payload := make([]byte, length)
	_, err = reader.Read(payload) // read from the 7th to the lenght of the payload
	if err != nil {
		return nil, fmt.Errorf("error reading payload %w", err)
	}

	for i := 0; i < length; i++ {
		payload[i] ^= mask[i%4]
	}

	return payload, nil
}

func sendCloseFrame(code uint16, reason string, conn net.Conn) error {
	codeLen := 2

	payload := make([]byte, codeLen+len(reason))
	// big-endian: most important byte first
	payload[0] = byte(code >> 8)
	payload[1] = byte(code)
	copy(payload[2:], []byte(reason))

	closeFrame := []byte{0x88}

	if len(payload) <= 125 {
		closeFrame = append(closeFrame, byte(len(payload)))
	} else {
		return errors.New("invalid closing reason length")
	}

	closeFrame = append(closeFrame, payload...)

	_, err := conn.Write(closeFrame)
	if err != nil {
		return fmt.Errorf("error sending close frame %w", err)
	}
	return nil
}

func sendToClient(conn net.Conn) error {
	msg := "hello from server"
	length := len(msg)
	response := []byte(msg)

	frame := []byte{textFrameByte}

	if length <= 125 {
		// response = [type, length, payload...]
		frame = append(frame, byte(length))
	} else if length <= 65535 {
		frame = append(frame, 126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(length))
		// response = [type, extended length (16 bits), byte len (8 bits) * 2, payload...]
		frame = append(frame, lenBytes...)
	} else {
		frame = append(frame, 127)
		lenBytes := make([]byte, 8)
		// response = [type, extended length (64 bits), byte len (8 bits) * 8 , payload...]
		binary.BigEndian.PutUint64(lenBytes, uint64(length))
		frame = append(frame, lenBytes...)
	}

	frame = append(frame, response...)

	_, err := conn.Write(frame)
	return err
}

func handleWebSocket(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		firstByte, err := reader.ReadByte() // 1st byte read
		if err != nil {
			sendCloseFrame(1001, err.Error(), conn)
			break
		}

		if firstByte == closeFrameByte {
			sendCloseFrame(1001, "connection close requested", conn)
			break
		}

		// 8 bits
		// 1st one tells if the payload has a mask (1 or 0)
		// the rest (7) have the length of the payload
		payloadLenByte, err := reader.ReadByte() // 2nd byte read
		if err != nil {
			sendCloseFrame(1001, err.Error(), conn)
			break
		}
		payloadLen := int(payloadLenByte & 0x7F) // here we access the length (7 bits from the byte)

		// Payload length:  7 bits, 7+16 bits, or 7+64 bits
		//
		// The length of the "Payload data", in bytes: if 0-125, that is the
		// payload length.  If 126, the following 2 bytes interpreted as a
		// 16-bit unsigned integer are the payload length.  If 127, the
		// following 8 bytes interpreted as a 64-bit unsigned integer (the
		// most significant bit MUST be 0) are the payload length.  Multibyte
		// length quantities are expressed in network byte order.  Note that
		// in all cases, the minimal number of bytes MUST be used to encode
		// the length, for example, the length of a 124-byte-long string
		// can't be encoded as the sequence 126, 0, 124.  The payload length
		// is the length of the "Extension data" + the length of the
		// "Application data".  The length of the "Extension data" may be
		// zero, in which case the payload length is the length of the
		// "Application data".
		var lenBytesN int
		switch payloadLen {
		case 126:
			lenBytesN = 2
		case 127:
			lenBytesN = 8
		default:
			lenBytesN = 0
		}

		if lenBytesN != 0 {
			lenBytes := make([]byte, lenBytesN)
			_, err = reader.Read(lenBytes)
			if err != nil {
				err := fmt.Sprintf("error reading long payload %s", err)
				sendCloseFrame(1001, err, conn)
				break
			}
			if lenBytesN == 2 {
				payloadLen = int(binary.BigEndian.Uint16(lenBytes))
			} else {
				payloadLen = int(binary.BigEndian.Uint64(lenBytes))
			}
		}

		payload, err := unmaskPayload(payloadLen, reader) // 3rd to 6th read (mask)
		if err != nil {
			sendCloseFrame(1001, err.Error(), conn)
			break
		}

		message := string(payload)
		fmt.Println("received message: ", len(message))

		err = sendToClient(conn)
		if err != nil {
			sendCloseFrame(1001, err.Error(), conn)
			break
		}
	}
}

func hijackConnection(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot hijack connection", http.StatusInternalServerError)
		return nil, fmt.Errorf("cannot hijack connection")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("error hijacking connection: %w", err)
	}

	return conn, nil
}

func getAcceptKey(key string) string {
	hash := sha1.New()
	hash.Write([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func buildWsConnHeaders(key string) string {
	// https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.2
	return fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n",
		getAcceptKey(key),
	)
}

func upgradeToWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key") // generated by the client and encoded in base64
	if key == "" {
		http.Error(w, "Bad Request: Sec-WebSocket-Key missing", http.StatusBadRequest)
		return nil, fmt.Errorf("Sec-WebSocket-Key missing")
	}

	headers := buildWsConnHeaders(key)
	conn, err := hijackConnection(w)

	_, err = conn.Write([]byte(headers))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func handleHTTPConnection(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "unsupported connection intent", http.StatusBadRequest)
		return
	}

	conn, err := upgradeToWebSocket(w, r)
	if err != nil {
		fmt.Println("error upgrading http connection to ws", err)
		return
	}

	handleWebSocket(conn)
}

func main() {
	http.HandleFunc("/ws", handleHTTPConnection)
	fmt.Println("server running on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("error starting ws server", err)
	}
}
