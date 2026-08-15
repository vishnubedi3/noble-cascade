#!/usr/bin/env python3
"""
Rate Limiting Middleware (TheArchitectit Agent Guardrails Template pattern)
Enforces sliding-window rate limits per tool call to prevent accidental DoS against targets.
"""

import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_calls=60, window_seconds=60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.calls = defaultdict(list)

    def check_rate_limit(self, tool_name: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        
        # Filter calls within window
        self.calls[tool_name] = [t for t in self.calls[tool_name] if t > window_start]
        
        if len(self.calls[tool_name]) >= self.max_calls:
            print(f"[!] Rate limit exceeded for tool '{tool_name}' ({len(self.calls[tool_name])} calls in {self.window_seconds}s). Throttled.")
            return False
            
        self.calls[tool_name].append(now)
        return True

if __name__ == "__main__":
    rl = RateLimiter(max_calls=5, window_seconds=10)
    for i in range(6):
        allowed = rl.check_rate_limit("fuzzer")
        print(f"Call {i+1}: allowed={allowed}")
