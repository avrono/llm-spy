// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT

package http2

import (
	"encoding/binary"
	"fmt"
)

// Frame types
const (
	FrameData         = 0x0
	FrameHeaders      = 0x1
	FramePriority     = 0x2
	FrameRSTStream    = 0x3
	FrameSettings     = 0x4
	FramePushPromise  = 0x5
	FramePing         = 0x6
	FrameGoAway       = 0x7
	FrameWindowUpdate = 0x8
	FrameContinuation = 0x9
)

// FrameHeader represents an HTTP/2 frame header (9 bytes)
type FrameHeader struct {
	Length   uint32 // 24-bit length
	Type     uint8
	Flags    uint8
	StreamID uint32 // 31-bit stream ID
}

// Frame represents a complete HTTP/2 frame
type Frame struct {
	Header  FrameHeader
	Payload []byte
}

// ParseFrameHeader parses the 9-byte HTTP/2 frame header
func ParseFrameHeader(data []byte) (*FrameHeader, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("insufficient data for frame header: %d bytes", len(data))
	}

	header := &FrameHeader{
		Length:   uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]),
		Type:     data[3],
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF, // Clear reserved bit
	}

	return header, nil
}

// ParseFrame extracts a complete frame from the buffer
func ParseFrame(data []byte) (*Frame, int, error) {
	header, err := ParseFrameHeader(data)
	if err != nil {
		return nil, 0, err
	}

	totalLen := 9 + int(header.Length)
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("incomplete frame: need %d bytes, have %d", totalLen, len(data))
	}

	frame := &Frame{
		Header:  *header,
		Payload: data[9:totalLen],
	}

	return frame, totalLen, nil
}

// ExtractDataFrames extracts all DATA frames from a buffer
func ExtractDataFrames(data []byte) [][]byte {
	var payloads [][]byte
	offset := 0

	for offset+9 <= len(data) {
		frame, consumed, err := ParseFrame(data[offset:])
		if err != nil {
			// Try to find next frame header
			offset++
			continue
		}

		if frame.Header.Type == FrameData && len(frame.Payload) > 0 {
			payloads = append(payloads, frame.Payload)
		}

		offset += consumed
	}

	return payloads
}

// IsHTTP2 checks if data looks like HTTP/2
func IsHTTP2(data []byte) bool {
	// Check for HTTP/2 connection preface
	if len(data) >= 24 && string(data[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return true
	}

	// Check for valid frame header
	if len(data) >= 9 {
		header, err := ParseFrameHeader(data)
		if err == nil && header.Type <= FrameContinuation {
			return true
		}
	}

	return false
}
