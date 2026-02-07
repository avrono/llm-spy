#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT

# REMOVED EXPLICIT PROXY SETTINGS
# llm-spy is a TRANSPARENT proxy (intercepts via eBPF). 
# Setting HTTPS_PROXY causes Electron to send HTTP CONNECT requests, which our proxy doesn't handle.
# export HTTPS_PROXY=http://localhost:8080
# export HTTP_PROXY=http://localhost:8080

export NODE_TLS_REJECT_UNAUTHORIZED=0
antigravity

