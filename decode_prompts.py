#!/usr/bin/env python3
"""
Real-time TShark protobuf decoder - PROMPT FOCUSED
Specifically designed to extract and decode LLM prompts, not telemetry
Usage: sudo ./capture_prompts.sh | python3 decode_prompts.py | tee decode_test.out
"""

import json
import sys
import base64
import subprocess
from datetime import datetime
import re

def decode_hex_or_base64(data_str):
    """Try to decode hex or base64 string to bytes"""
    if not data_str:
        return None
    
    # Remove colons (hex format from tshark)
    clean = data_str.replace(':', '')
    
    # Try hex first
    try:
        return bytes.fromhex(clean)
    except:
        pass
    
    # Try base64
    try:
        return base64.b64decode(data_str)
    except:
        pass
    
    return None

def decode_protobuf_raw(data):
    """Decode protobuf using protoc --decode_raw"""
    try:
        result = subprocess.run(
            ['protoc', '--decode_raw'],
            input=data,
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.decode('utf-8', errors='ignore')
    except:
        pass
    return None

def extract_strings(data, min_length=10):
    """Extract printable ASCII/UTF-8 strings from binary data"""
    strings = []
    current = ""
    
    for byte in data:
        # Printable ASCII + common UTF-8 ranges
        if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Include tab, newline, CR
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ""
    
    if len(current) >= min_length:
        strings.append(current)
    
    return strings

def looks_like_prompt(text):
    """Heuristic to detect if text looks like an LLM prompt"""
    prompt_indicators = [
        'user', 'assistant', 'system', 'message', 'content',
        'role', 'prompt', 'instruction', 'task', 'question',
        'write', 'create', 'explain', 'help', 'generate',
        'file:', 'function', 'code', 'implement', 'debug',
        'workspace', 'repository', 'project'
    ]
    
    text_lower = text.lower()
    matches = sum(1 for indicator in prompt_indicators if indicator in text_lower)
    
    # If we have multiple indicators and reasonable length, likely a prompt
    return matches >= 3 and len(text) > 50

def extract_prompt_content(protobuf_text):
    """Extract likely prompt content from protobuf decoded text"""
    prompts = []
    
    # Look for field 2 (often the content field in protobuf)
    # Pattern: 2: "actual content here"
    pattern = r'(\d+):\s*"([^"]{50,})"'
    matches = re.findall(pattern, protobuf_text, re.MULTILINE | re.DOTALL)
    
    for field_num, content in matches:
        if looks_like_prompt(content):
            prompts.append({
                'field': field_num,
                'content': content,
                'length': len(content)
            })
    
    return prompts

def analyze_http2_headers(header_names, header_values):
    """Analyze HTTP/2 headers to determine request type"""
    headers = {}
    if header_names and header_values:
        for name, value in zip(header_names, header_values):
            headers[name] = value
    
    # Look for method and path
    method = headers.get(':method', '')
    path = headers.get(':path', '')
    content_type = headers.get('content-type', '')
    
    is_request = method == 'POST'
    is_protobuf = 'protobuf' in content_type or 'grpc' in content_type
    
    return {
        'method': method,
        'path': path,
        'content_type': content_type,
        'is_request': is_request,
        'is_protobuf': is_protobuf
    }

def process_packet(packet_json):
    """Process a single TShark JSON packet"""
    try:
        layers = packet_json.get('_source', {}).get('layers', {})
        
        # Get timestamp
        timestamp = layers.get('frame.time_epoch', [''])[0]
        if timestamp:
            dt = datetime.fromtimestamp(float(timestamp))
            time_str = dt.strftime('%H:%M:%S.%f')[:-3]
        else:
            time_str = 'Unknown'
        
        # Get frame info
        frame_num = layers.get('frame.number', [''])[0]
        frame_len = layers.get('frame.len', [''])[0]
        
        # Get domain (SNI)
        sni = layers.get('tls.handshake.extensions_server_name', [''])[0]
        
        # Get HTTP/2 headers
        header_names = layers.get('http2.header.name', [])
        header_values = layers.get('http2.header.value', [])
        http2_info = analyze_http2_headers(header_names, header_values)
        
        # Get HTTP/2 data
        http2_data_list = layers.get('http2.data.data', [])
        
        if not http2_data_list:
            return  # Skip packets without data
        
        # Process all data fields
        for data_field in http2_data_list:
            if not data_field:
                continue
            
            # Decode the data
            decoded = decode_hex_or_base64(data_field)
            if not decoded:
                continue
            
            # Skip small payloads (likely not prompts)
            if len(decoded) < 100:
                continue
            
            print(f"\n{'='*80}")
            print(f"📦 Frame #{frame_num} | ⏰ {time_str} | 📏 {frame_len} bytes")
            if sni:
                print(f"🌐 Domain: {sni}")
            if http2_info['method']:
                print(f"🔧 Method: {http2_info['method']} | 📍 Path: {http2_info['path']}")
            if http2_info['content_type']:
                print(f"📋 Content-Type: {http2_info['content_type']}")
            print(f"{'='*80}")
            
            # Try protobuf decode
            protobuf_output = decode_protobuf_raw(decoded)
            if protobuf_output:
                print("\n🧩 Protobuf Structure:")
                print("-" * 80)
                
                # Extract potential prompts
                prompts = extract_prompt_content(protobuf_output)
                
                if prompts:
                    print(f"✨ FOUND {len(prompts)} POTENTIAL PROMPT(S)!")
                    print("-" * 80)
                    for i, prompt_info in enumerate(prompts, 1):
                        print(f"\n🎯 Prompt #{i} (Field {prompt_info['field']}, {prompt_info['length']} chars):")
                        print("─" * 80)
                        # Pretty print the content
                        content = prompt_info['content']
                        # Unescape common sequences
                        content = content.replace('\\n', '\n').replace('\\t', '\t')
                        print(content)
                        print("─" * 80)
                else:
                    # Show raw protobuf structure (first 100 lines)
                    all_lines = protobuf_output.split('\n')
                    lines = all_lines[:100]
                    print('\n'.join(lines))
                    if len(all_lines) > 100:
                        remaining = len(all_lines) - 100
                        print(f"... ({remaining} more lines)")
                
                print("-" * 80)
            
            # Extract readable strings as fallback
            strings = extract_strings(decoded, min_length=20)
            if strings:
                # Filter for likely prompt content
                prompt_strings = [s for s in strings if looks_like_prompt(s)]
                
                if prompt_strings:
                    print("\n📝 Likely Prompt Strings:")
                    print("-" * 80)
                    for s in prompt_strings[:10]:
                        # Clean up the string
                        clean = s.strip().replace('\\n', '\n')
                        print(f"  💬 {clean[:500]}")
                        if len(clean) > 500:
                            print(f"     ... ({len(clean) - 500} more chars)")
                    print("-" * 80)
            
            print()
    
    except Exception as e:
        print(f"[ERROR] Exception processing packet: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)

def main():
    print("🎯 Real-Time Prompt Decoder (Focused on LLM Prompts)")
    print("Waiting for TShark data...")
    print("=" * 80)
    
    # Buffer to accumulate JSON lines
    json_buffer = ""
    in_json_object = False
    brace_count = 0
    packet_count = 0
    
    for line in sys.stdin:
        # Skip non-JSON lines
        if not in_json_object and not line.strip().startswith(('[', '{')):
            continue
        
        # Track JSON object boundaries
        for char in line:
            if char == '{':
                brace_count += 1
                in_json_object = True
            elif char == '}':
                brace_count -= 1
        
        json_buffer += line
        
        # When we have a complete JSON object
        if in_json_object and brace_count == 0:
            try:
                # Remove trailing commas and array markers
                clean_json = json_buffer.strip().rstrip(',').strip('[]')
                if clean_json:
                    packet = json.loads(clean_json)
                    packet_count += 1
                    if packet_count % 10 == 0:
                        print(f"[INFO] Processed {packet_count} packets so far", file=sys.stderr)
                    process_packet(packet)
            except json.JSONDecodeError as e:
                # Silently skip malformed JSON
                pass
            except KeyboardInterrupt:
                print("\n\n👋 Stopping decoder...")
                break
            finally:
                # Reset buffer
                json_buffer = ""
                in_json_object = False

if __name__ == '__main__':
    main()
