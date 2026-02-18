#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT

# Prompt-focused SSL capture script for LLM traffic monitoring
# This script specifically targets PROMPT data, not telemetry
# Usage: sudo ./capture_prompts.sh [interface] [keylog_file]

INTERFACE=${1:-any}
KEYLOG=${2:-/tmp/sslkeys.log}

echo "🎯 Starting Prompt-Focused TShark LLM Capture"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📡 Interface: $INTERFACE"
echo "🔑 Keylog File: $KEYLOG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo "❌ tshark not found. Please install it: sudo apt install tshark"
    exit 1
fi

# Check if keylog file exists
if [[ ! -f "$KEYLOG" ]]; then
    echo "⚠️  Warning: Keylog file not found at $KEYLOG"
    echo "   Make sure to set SSLKEYLOGFILE environment variable for your client:"
    echo "   export SSLKEYLOGFILE=$KEYLOG"
    echo ""
fi

echo "🎯 Filtering for LLM PROMPT traffic..."
echo "   Target: daily-cloudcode-pa.googleapis.com (Antigravity backend)"
echo "   Looking for: Large HTTP/2 POST requests (prompts are big!)"
echo ""
echo "⏳ Waiting for traffic..."
echo ""

# Strategy for capturing PROMPTS not telemetry:
# 1. Filter for HTTP/2 DATA frames (where payload lives)
# 2. Look for larger payloads (prompts are typically > 500 bytes)
# 3. Capture both request and response direction
# 4. Focus on googleapis.com domain

sudo tshark \
    -i "$INTERFACE" \
    -o "tls.keylog_file:$KEYLOG" \
    \
    -Y "http2.data.data and frame.len > 500" \
    \
    -T json \
    \
    -e frame.number \
    -e frame.time_epoch \
    -e frame.len \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tls.handshake.extensions_server_name \
    \
    -e http2.streamid \
    -e http2.header.name \
    -e http2.header.value \
    -e http2.data.data \
    -e http2.type \
    -e http2.length \
    \
    -e http.request.method \
    -e http.request.uri \
    -e http.content_type \
    \
    -l \
    2>/dev/null
