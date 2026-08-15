# Secure Code Review Skill (Anthropic Cybersecurity Skills)

## Core Principles
1. **Trace Source to Sink:** For every user input, follow its propagation to any sink (SQL query, shell command, HTML renderer, file write) to verify proper sanitization.
2. **Least Privilege:** Verify that components, database roles, and API endpoints operate with minimal required privileges.
3. **Defense in Depth:** Check for multi-layered defenses (input validation + parameterized queries + output encoding).
