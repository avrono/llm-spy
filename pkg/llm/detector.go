// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT

package llm

import (
	"strings"
)

// Provider represents an LLM API provider
type Provider string

const (
	ProviderOpenAI    Provider = "OpenAI"
	ProviderAnthropic Provider = "Anthropic"
	ProviderGoogle    Provider = "Google"
	ProviderCohere    Provider = "Cohere"
	ProviderUnknown   Provider = "Unknown"
)

// Detection patterns for each provider
var providerPatterns = map[Provider][]string{
	ProviderOpenAI: {
		"api.openai.com",
		"\"model\":\"gpt-",
		"chat/completions",
		"/v1/completions",
		"/v1/embeddings",
	},
	ProviderAnthropic: {
		"api.anthropic.com",
		"\"model\":\"claude-",
		"/v1/messages",
		"x-api-key",
		"anthropic-version",
	},
	ProviderGoogle: {
		"generativelanguage.googleapis.com",
		"\"model\":\"gemini-",
		"\"model\":\"models/gemini-",
		"generateContent",
	},
	ProviderCohere: {
		"api.cohere.ai",
		"/v1/generate",
		"/v1/chat",
	},
}

// RequestIndicators are patterns that suggest this is a request
var RequestIndicators = []string{
	"POST /",
	"\"messages\":[",
	"\"prompt\":",
	"\"model\":",
	"Content-Type: application/json",
}

// ResponseIndicators are patterns that suggest this is a response
var ResponseIndicators = []string{
	"HTTP/2 200",
	"HTTP/1.1 200",
	"\"choices\":[",
	"\"content\":[",
	"data: {",
	"\"id\":\"chatcmpl-",
}

// DetectProvider identifies which LLM provider this traffic belongs to
func DetectProvider(payload string) Provider {
	lowerPayload := strings.ToLower(payload)

	for provider, patterns := range providerPatterns {
		for _, pattern := range patterns {
			if strings.Contains(lowerPayload, strings.ToLower(pattern)) {
				return provider
			}
		}
	}

	return ProviderUnknown
}

// IsLLMTraffic checks if payload appears to be LLM-related
func IsLLMTraffic(payload string) bool {
	return DetectProvider(payload) != ProviderUnknown
}

// IsRequest checks if this looks like an LLM API request
func IsRequest(payload string) bool {
	for _, indicator := range RequestIndicators {
		if strings.Contains(payload, indicator) {
			return true
		}
	}
	return false
}

// IsResponse checks if this looks like an LLM API response
func IsResponse(payload string) bool {
	for _, indicator := range ResponseIndicators {
		if strings.Contains(payload, indicator) {
			return true
		}
	}
	return false
}

// IsStreaming checks if this is a streaming response (SSE)
func IsStreaming(payload string) bool {
	return strings.Contains(payload, "data: {") ||
		strings.Contains(payload, "event:") ||
		(strings.Contains(payload, "data:") && strings.Contains(payload, "[DONE]"))
}
