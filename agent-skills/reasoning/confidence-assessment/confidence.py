#!/usr/bin/env python3
"""
Confidence Assessment Engine (NVIDIA SkillSpector pattern)
Computes 0-100 confidence and risk scores for findings based on evidence strength.
"""

import sys
import json

def assess_confidence(evidence_strength: int, reproducibility: bool, disproof_resilience: bool) -> dict:
    score = 50
    if evidence_strength >= 8:
        score += 25
    if reproducibility:
        score += 15
    if disproof_resilience:
        score += 10

    score = min(100, max(0, score))
    
    level = "LOW"
    if score >= 80:
        level = "HIGH"
    elif score >= 60:
        level = "MEDIUM"

    return {"confidence_score": score, "confidence_level": level}

if __name__ == "__main__":
    result = assess_confidence(9, True, True)
    print(json.dumps(result, indent=2))
