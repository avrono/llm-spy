#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT

# usage: ./run_unsafe.sh <command_to_run>
# Example: ./run_unsafe.sh code
# Example: ./run_unsafe.sh google-chrome

echo "⚠️  Launching application with SSL Verification DISABLED..."
echo "    This allows it to trust the llm-spy transparent proxy."

# 1. Environment variable for Node.js / Electron apps (VSCode, Antigravity, etc.)
export NODE_TLS_REJECT_UNAUTHORIZED=0

# 2. Command line flags for Chromium/Electron based apps
# We try to pass them to the command provided
"$@" \
  --ignore-certificate-errors \
  --ignore-ssl-errors \
  --ignore-certificate-errors-spki-list \
  --user-data-dir="/tmp/chrome-unsafe-testing-$$" \
  --no-first-run
