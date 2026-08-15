#!/usr/bin/env python3
"""
Language and Framework Detection (SecOpsAgentKit pattern)
Scans workspace files to detect programming languages, frameworks, and build tools.
"""

import os
import json

EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".tf": "Terraform",
    ".yaml": "YAML/Config",
    ".json": "JSON/Config"
}

MANIFESTS = {
    "package.json": "Node.js / npm",
    "requirements.txt": "Python / pip",
    "pyproject.toml": "Python / Poetry-Flit",
    "go.mod": "Go Modules",
    "Cargo.toml": "Rust Cargo",
    "pom.xml": "Java Maven",
    "Dockerfile": "Docker Container"
}

def detect_stack(root_dir="."):
    detected_langs = set()
    detected_frameworks = []
    
    for dirpath, _, filenames in os.walk(root_dir):
        if ".git" in dirpath or "node_modules" in dirpath or "agent-skills" in dirpath:
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1]
            if ext in EXTENSIONS:
                detected_langs.add(EXTENSIONS[ext])
            if f in MANIFESTS:
                detected_frameworks.append(MANIFESTS[f])

    result = {
        "languages": list(detected_langs),
        "build_systems": detected_frameworks
    }
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    detect_stack()
