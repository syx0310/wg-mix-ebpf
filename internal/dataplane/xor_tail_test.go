package dataplane

import (
	"bytes"
	"strconv"
	"testing"
)

func TestXORByteTailIncrementalChecksum(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i*29 + 7)
	}

	for _, payloadLen := range []int{
		32, 33, 34, 35,
		253, 254, 255, 256,
		257, 258, 259,
		2045, 2046, 2047, 2048,
	} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			cleartext := make([]byte, payloadLen)
			for i := range cleartext {
				cleartext[i] = byte(i*17 + 3)
			}
			// This even-length prefix represents the unchanged pseudo-header
			// and UDP header that precede the WireGuard payload.
			checksumPrefix := []byte{
				0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
				0x00, 0x11, 0x00, 0x00, 0x79, 0x19, 0x79, 0x1a,
				0x00, 0x00, 0x00, 0x00,
			}

			encrypted := append([]byte(nil), cleartext...)
			checksum := internetChecksum(appendCopy(checksumPrefix, encrypted))
			checksum = xorChecksumSegments(encrypted, key, 0, checksum)
			if want := internetChecksum(appendCopy(checksumPrefix, encrypted)); checksum != want {
				t.Fatalf("egress incremental checksum = %#04x, want %#04x", checksum, want)
			}

			// Ingress replaces the encrypted type word separately, then starts
			// the segmented XOR pass at byte four. Model that split so the test
			// also guards the key offset used by the ingress byte tail.
			checksum = xorChecksumRange(encrypted, key, 0, 4, checksum)
			checksum = xorChecksumSegments(encrypted, key, 4, checksum)
			if want := internetChecksum(appendCopy(checksumPrefix, encrypted)); checksum != want {
				t.Fatalf("ingress incremental checksum = %#04x, want %#04x", checksum, want)
			}
			if !bytes.Equal(encrypted, cleartext) {
				t.Fatal("XOR byte-tail round trip did not restore the payload")
			}
		})
	}
}

func TestXORByteTailStoreOnlyRoundTrip(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i*11 + 5)
	}

	for _, payloadLen := range []int{32, 33, 34, 35, 255, 256, 257, 2047, 2048} {
		payload := make([]byte, payloadLen)
		for i := range payload {
			payload[i] = byte(i*13 + 1)
		}
		want := append([]byte(nil), payload...)

		xorStoreSegments(payload, key, 0)
		xorStoreRange(payload, key, 0, 4)
		xorStoreSegments(payload, key, 4)

		if !bytes.Equal(payload, want) {
			t.Fatalf("payload length %d did not round trip", payloadLen)
		}
	}
}

const xorTestSegmentBytes = 256

func xorChecksumSegments(payload, key []byte, start int, checksum uint16) uint16 {
	for segmentStart := 0; segmentStart < len(payload); segmentStart += xorTestSegmentBytes {
		segmentEnd := segmentStart + xorTestSegmentBytes
		if segmentEnd > len(payload) {
			segmentEnd = len(payload)
		}
		processed := segmentStart
		if processed < start {
			processed = start
		}
		if processed < segmentEnd {
			checksum = xorChecksumRange(payload, key, processed, segmentEnd, checksum)
		}
	}
	return checksum
}

func xorChecksumRange(payload, key []byte, start, end int, checksum uint16) uint16 {
	for processed := start; processed < end; {
		size := 4
		if remaining := end - processed; remaining < size {
			size = remaining
		}
		oldWord := make([]byte, 4)
		newWord := make([]byte, 4)
		copy(oldWord, payload[processed:processed+size])
		for i := 0; i < size; i++ {
			newWord[i] = oldWord[i] ^ key[(processed+i)&255]
			payload[processed+i] = newWord[i]
		}
		checksum = replaceChecksum(checksum, oldWord, newWord)
		processed += size
	}
	return checksum
}

func xorStoreSegments(payload, key []byte, start int) {
	for segmentStart := 0; segmentStart < len(payload); segmentStart += xorTestSegmentBytes {
		segmentEnd := segmentStart + xorTestSegmentBytes
		if segmentEnd > len(payload) {
			segmentEnd = len(payload)
		}
		processed := segmentStart
		if processed < start {
			processed = start
		}
		xorStoreRange(payload, key, processed, segmentEnd)
	}
}

func xorStoreRange(payload, key []byte, start, end int) {
	for i := start; i < end; i++ {
		payload[i] ^= key[i&255]
	}
}

func replaceChecksum(checksum uint16, oldData, newData []byte) uint16 {
	sum := uint32(^checksum)
	for i := 0; i < len(oldData); i += 2 {
		oldWord := uint16(oldData[i]) << 8
		newWord := uint16(newData[i]) << 8
		if i+1 < len(oldData) {
			oldWord |= uint16(oldData[i+1])
			newWord |= uint16(newData[i+1])
		}
		sum += uint32(^oldWord) + uint32(newWord)
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		word := uint16(data[i]) << 8
		if i+1 < len(data) {
			word |= uint16(data[i+1])
		}
		sum += uint32(word)
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

func appendCopy(prefix, payload []byte) []byte {
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	return append(out, payload...)
}
