package jsonutil

import (
	"strings"
	"testing"
)

func TestFormatLLMRequest_MissingFields(t *testing.T) {
	// Case 1: All fields present
	fullObj := map[string]interface{}{
		"model": "gpt-4",
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "Hello"},
		},
	}
	output := FormatLLMRequest(fullObj)
	if !strings.Contains(output, "Model: gpt-4") || !strings.Contains(output, "Hello") {
		t.Errorf("Expected model and content in output, got: %s", output)
	}
	if strings.Contains(output, "Raw JSON") {
		t.Errorf("Did not expect Raw JSON for full object, got: %s", output)
	}

	// Case 2: Only Model present (simulate missing prompt)
	partialObj := map[string]interface{}{
		"model": "gpt-4",
		// messages missing
		"unknown_field": "some data",
	}
	output = FormatLLMRequest(partialObj)
	t.Logf("Output for partial obj:\n%s", output)

	if !strings.Contains(output, "Raw JSON") {
		t.Errorf("Expected Raw JSON fallback when content is missing, got: %s", output)
	}

	// Case 3: No standard fields
	unknownObj := map[string]interface{}{
		"custom": "data",
	}
	output = FormatLLMRequest(unknownObj)
	if !strings.Contains(output, "Raw JSON") {
		t.Errorf("Expected Raw JSON fallback for unknown object, got: %s", output)
	}
}
