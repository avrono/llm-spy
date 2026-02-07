#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT
# Complete setup script to capture Antigravity LLM traffic

echo "🔧 Setting up llm-spy to capture Antigravity traffic..."
echo ""

# 1. Kill any existing llm-spy
echo "1. Stopping existing llm-spy..."
sudo pkill -f "llm-spy" 2>/dev/null || true
sleep 2

# 2. Clean up old log
rm -f test_formatted.log

# 3. Start llm-spy FIRST
echo "2. Starting llm-spy proxy..."
sudo ./llm-spy --proxy --port 8080 --output test_formatted.log &
LLMSPY_PID=$!
sleep 3

# 4. Restart Antigravity to force new connections through proxy
echo "3. Restarting Antigravity to route through proxy..."
echo "   (This will close your IDE - save your work first!)"
read -p "   Press Enter to continue or Ctrl+C to cancel..."

killall antigravity 2>/dev/null || true
sleep 2

# Start Antigravity
echo "4. Starting Antigravity..."
NODE_TLS_REJECT_UNAUTHORIZED=0 && /usr/share/antigravity/antigravity &
sleep 5

echo ""
echo "✅ Setup complete!"
echo "📝 Logging to: test_formatted.log"
echo "🔍 llm-spy PID: $LLMSPY_PID"
echo ""
echo "Now use Antigravity and send prompts. Check logs with:"
echo "  tail -f test_formatted.log"
echo ""
echo "Press Ctrl+C to stop llm-spy when done."
echo ""

# Keep script running
wait $LLMSPY_PID
