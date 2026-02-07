// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT

package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractJSON finds and extracts JSON objects from a byte buffer
func ExtractJSON(data []byte) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	// Try to decode as a single JSON object first
	var singleObj map[string]interface{}
	if err := json.Unmarshal(data, &singleObj); err == nil {
		return []map[string]interface{}{singleObj}, nil
	}

	// Search for JSON objects in the data
	dataStr := string(data)
	bracketCount := 0
	startIdx := -1

	for i, ch := range dataStr {
		if ch == '{' {
			if bracketCount == 0 {
				startIdx = i
			}
			bracketCount++
		} else if ch == '}' {
			bracketCount--
			if bracketCount == 0 && startIdx != -1 {
				// Complete JSON object found
				jsonStr := dataStr[startIdx : i+1]
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(jsonStr), &obj); err == nil {
					results = append(results, obj)
				}
				startIdx = -1
			}
		}
	}

	return results, nil
}

// PrettyPrint formats JSON with indentation
func PrettyPrint(data interface{}) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// ExtractLLMFields extracts relevant fields from LLM API JSON
func ExtractLLMFields(obj map[string]interface{}) map[string]interface{} {
	fields := make(map[string]interface{})

	// Common fields across providers
	importantKeys := []string{
		"model", "messages", "prompt", "max_tokens", "temperature",
		"choices", "content", "role", "finish_reason",
		"usage", "id", "stream", "stop_reason",
	}

	for _, key := range importantKeys {
		if val, exists := obj[key]; exists {
			fields[key] = val
		}
	}

	return fields
}

// FormatLLMRequest formats an LLM request for display
func FormatLLMRequest(obj map[string]interface{}) string {
	var sb strings.Builder

	sb.WriteString("🤖 LLM API REQUEST\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	// Track if we found the ACTUAL content (messages or prompt)
	foundBody := false

	if model, ok := obj["model"].(string); ok {
		sb.WriteString(fmt.Sprintf("Model: %s\n", model))
	}

	if messages, ok := obj["messages"].([]interface{}); ok {
		sb.WriteString(fmt.Sprintf("Messages: %d\n", len(messages)))
		for i, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				role := msgMap["role"]
				content := msgMap["content"]
				sb.WriteString(fmt.Sprintf("  [%d] %v: %v\n", i+1, role, content))
			}
		}
		foundBody = true
	} else if prompt, ok := obj["prompt"].(string); ok {
		sb.WriteString(fmt.Sprintf("Prompt: %s\n", prompt))
		foundBody = true
	}

	if temp, ok := obj["temperature"].(float64); ok {
		sb.WriteString(fmt.Sprintf("Temperature: %.2f\n", temp))
	}

	if maxTokens, ok := obj["max_tokens"].(float64); ok {
		sb.WriteString(fmt.Sprintf("Max Tokens: %.0f\n", maxTokens))
	}

	// Fallback: If no body content (prompt/messages) found, dump raw JSON
	// This ensures we don't hide the request just because we found a model name
	if !foundBody {
		pretty, _ := PrettyPrint(obj)
		sb.WriteString(fmt.Sprintf("\n⚠️  Standard prompt/messages not found. Raw JSON:\n%s\n", pretty))
	}

	return sb.String()
}

// FormatLLMResponse formats an LLM response for display
func FormatLLMResponse(obj map[string]interface{}) string {
	var sb strings.Builder

	sb.WriteString("💬 LLM API RESPONSE\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	foundBody := false

	if id, ok := obj["id"].(string); ok {
		sb.WriteString(fmt.Sprintf("ID: %s\n", id))
	}

	if model, ok := obj["model"].(string); ok {
		sb.WriteString(fmt.Sprintf("Model: %s\n", model))
	}

	if choices, ok := obj["choices"].([]interface{}); ok {
		for i, choice := range choices {
			if choiceMap, ok := choice.(map[string]interface{}); ok {
				sb.WriteString(fmt.Sprintf("\nChoice %d:\n", i+1))

				if message, ok := choiceMap["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						sb.WriteString(fmt.Sprintf("  Content: %s\n", content))
					}
				}

				if finishReason, ok := choiceMap["finish_reason"].(string); ok {
					sb.WriteString(fmt.Sprintf("  Finish Reason: %s\n", finishReason))
				}
			}
		}
		foundBody = true
	} else if content, ok := obj["content"].([]interface{}); ok {
		// Anthropic format
		for _, item := range content {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if text, ok := itemMap["text"].(string); ok {
					sb.WriteString(fmt.Sprintf("Content: %s\n", text))
				}
			}
		}
		foundBody = true
	}

	if usage, ok := obj["usage"].(map[string]interface{}); ok {
		sb.WriteString("\nToken Usage:\n")
		for k, v := range usage {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}

	// Fallback for response body
	if !foundBody {
		pretty, _ := PrettyPrint(obj)
		sb.WriteString(fmt.Sprintf("\n⚠️  Standard response content not found. Raw JSON:\n%s\n", pretty))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	// No truncation
	return s
}
