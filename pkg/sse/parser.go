// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT

package sse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Event represents a Server-Sent Event
type Event struct {
	Event string
	Data  string
	ID    string
}

// ParseEvents parses SSE events from a buffer
func ParseEvents(data []byte) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var currentEvent Event

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line indicates end of event
			if currentEvent.Data != "" {
				events = append(events, currentEvent)
			}
			currentEvent = Event{}
			continue
		}

		// Parse field
		if strings.HasPrefix(line, "event:") {
			currentEvent.Event = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "data:") {
			dataContent := strings.TrimSpace(line[5:])
			if currentEvent.Data != "" {
				currentEvent.Data += "\n" + dataContent
			} else {
				currentEvent.Data = dataContent
			}
		} else if strings.HasPrefix(line, "id:") {
			currentEvent.ID = strings.TrimSpace(line[3:])
		}
	}

	// Add final event if exists
	if currentEvent.Data != "" {
		events = append(events, currentEvent)
	}

	return events, scanner.Err()
}

// StreamChunk represents a parsed streaming response chunk
type StreamChunk struct {
	Delta        string
	FinishReason string
	Model        string
}

// ParseStreamingChunk parses an SSE data field as JSON and extracts delta
func ParseStreamingChunk(dataField string) (*StreamChunk, error) {
	// Handle [DONE] marker
	if strings.TrimSpace(dataField) == "[DONE]" {
		return &StreamChunk{FinishReason: "done"}, nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(dataField), &obj); err != nil {
		return nil, err
	}

	chunk := &StreamChunk{}

	// Extract model
	if model, ok := obj["model"].(string); ok {
		chunk.Model = model
	}

	// Extract delta content (OpenAI format)
	if choices, ok := obj["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if delta, ok := choice["delta"].(map[string]interface{}); ok {
				if content, ok := delta["content"].(string); ok {
					chunk.Delta = content
				}
			}
			if finishReason, ok := choice["finish_reason"]; ok && finishReason != nil {
				chunk.FinishReason = fmt.Sprint(finishReason)
			}
		}
	}

	// Extract delta content (Anthropic format)
	if delta, ok := obj["delta"].(map[string]interface{}); ok {
		if text, ok := delta["text"].(string); ok {
			chunk.Delta = text
		}
	}

	if stopReason, ok := obj["stop_reason"].(string); ok {
		chunk.FinishReason = stopReason
	}

	return chunk, nil
}

// AggregateStreamingResponse combines streaming chunks into full response
type StreamAggregator struct {
	Content      strings.Builder
	Model        string
	ChunkCount   int
	FinishReason string
}

// AddChunk adds a streaming chunk to the aggregator
func (a *StreamAggregator) AddChunk(chunk *StreamChunk) {
	if chunk.Delta != "" {
		a.Content.WriteString(chunk.Delta)
	}
	if chunk.Model != "" && a.Model == "" {
		a.Model = chunk.Model
	}
	if chunk.FinishReason != "" {
		a.FinishReason = chunk.FinishReason
	}
	a.ChunkCount++
}

// GetFullResponse returns the complete aggregated response
func (a *StreamAggregator) GetFullResponse() string {
	return fmt.Sprintf("Model: %s\nChunks: %d\nFinish Reason: %s\n\nContent:\n%s",
		a.Model, a.ChunkCount, a.FinishReason, a.Content.String())
}
