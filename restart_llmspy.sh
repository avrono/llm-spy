#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT
# Quick restart script for llm-spy with new binary

echo "🔄 Restarting llm-spy with fixed binary..."

# Kill old processes
echo "Stopping old llm-spy..."
sudo pkill -f "llm-spy"
sleep 2

# Clean up old log
rm -f test_formatted.log

# Start new binary
echo "Starting new llm-spy..."
sudo ./llm-spy --proxy --port 8080 --output test_formatted.log &

sleep 2
echo ""
echo "✅ llm-spy restarted!"
echo "📝 Logging to: test_formatted.log"
echo ""
echo "Now send a prompt through Antigravity and check:"
echo "  tail -f test_formatted.log"
