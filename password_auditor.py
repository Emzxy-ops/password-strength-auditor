#!/usr/bin/env python3
"""
Network Security Tool: Password Strength Auditor
Author: [Emmanuel B. Onavewu]
Description: Analyzes password complexity against standard security policies
(NIST guidelines) to prevent brute-force and dictionary attacks.
"""

import string
import sys

def check_strength(password):
    # --- Setting up initial variables ---
    score = 0
    length_error = False
    feedback = []
    
    # Security strenght_report
    criteria = {
        "length": False,
        "upper": False,
        "lower": False,
        "digit": False,
        "symbol": False
    }

    # --- Check if password meets minimum length (8 chars) ---
    if len(password) >= 8:
        score += 1
        criteria["length"] = True
    else:
        length_error = True
        feedback.append("❌ Vulnerability: Password too short (Risk of Brute Force).")

    # --- 2. Complexity Analysis ---
    for char in password:
        if char in string.ascii_uppercase: criteria["upper"] = True
        if char in string.ascii_lowercase: criteria["lower"] = True
        if char in string.digits: criteria["digit"] = True
        if char in string.punctuation: criteria["symbol"] = True

    # --- 3. Scoring & Feedback ---
    # Upper Case
    if criteria["upper"]:
        score += 1
    else:
        feedback.append("⚠️ Weakness: No Uppercase letters.")

    # Lower Case
    if criteria["lower"]:
        score += 1
    else:
        feedback.append("⚠️ Weakness: No Lowercase letters.")

    # Digits
    if criteria["digit"]:
        score += 1
    else:
        feedback.append("⚠️ Weakness: No Numeric digits.")

    # Symbols
    if criteria["symbol"]:
        score += 1
    else:
        feedback.append("⚠️ Weakness: No Special characters.")

    return score, feedback

# --- Main Execution ---
if __name__ == "__main__":
    print("--- 🔒 NETWORK SECURITY PASSWORD AUDITOR 🔒 ---")
    try:
        user_pass = input("Enter password to audit: ")
        
        final_score, report = check_strength(user_pass)

        print("\n--- AUDIT REPORT ---")
        for item in report:
            print(item)
            
        print("-" * 30)
        if final_score <= 2:
            print(f"RESULT: WEAK 🔴 (Score: {final_score}/5)")
            print("Recommendation: Change immediately.")
        elif final_score <= 4:
            print(f"RESULT: MODERATE 🟡 (Score: {final_score}/5)")
            print("Recommendation: Enable 2FA if possible.")
        else:
            print(f"RESULT: STRONG 🟢 (Score: {final_score}/5)")
            print("Status: Meets Complex Security Standards.")
            
    except KeyboardInterrupt:
        print("\n\nAudit cancelled by user.")
        sys.exit()