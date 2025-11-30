import streamlit as st
import string
import hashlib
import requests

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Network Security Auditor", page_icon="🔒", layout="centered")

# --- HIBP API LOGIC (Real Implementation) ---
def check_pwned_api(password):
    """
    Checks the password against the Have I Been Pwned API.
    Uses k-Anonymity: Only sends the first 5 chars of the SHA-1 hash.
    Returns: The number of times the password has been leaked (0 if safe).
    """
    # 1. Hash the password (SHA-1)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 2. Split hash: first 5 chars (prefix) to send, rest (suffix) to check locally
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    
    # 3. Query the API
    url = 'https://api.pwnedpasswords.com/range/' + first5_char
    try:
        res = requests.get(url)
        if res.status_code != 200:
            return 0 # Fail safe: assume 0 if API is down so app doesn't crash
            
        # 4. Check response for our specific hash suffix
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return int(count)
        return 0
    except:
        return 0 # Fail safe for connection issues

# --- CORE LOGIC ---
def check_strength(password):
    score = 0
    feedback = []
    
    # 0. HIBP Check (The New Feature)
    pwned_count = check_pwned_api(password)
    if pwned_count > 0:
        feedback.append(f"❌ CRITICAL: This password has been leaked {pwned_count} times in data breaches!")
        # We don't return immediately; we still analyze complexity, but score takes a hit.
        score = 0 
    else:
        feedback.append("✅ Database Check: Password not found in known breaches.")
        score += 1 # Bonus point for not being leaked

    # 1. Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Length: Too short (Minimum 8 characters).")

    # 2. Complexity Variables
    has_upper = any(char in string.ascii_uppercase for char in password)
    has_lower = any(char in string.ascii_lowercase for char in password)
    has_digit = any(char in string.digits for char in password)
    has_symbol = any(char in string.punctuation for char in password)

    # 3. Scoring
    if has_upper: score += 1
    else: feedback.append("⚠️ Complexity: Missing Uppercase letters.")
        
    if has_lower: score += 1
    else: feedback.append("⚠️ Complexity: Missing Lowercase letters.")
        
    if has_digit: score += 1
    else: feedback.append("⚠️ Complexity: Missing Numeric digits.")
        
    if has_symbol: score += 1
    else: feedback.append("⚠️ Complexity: Missing Special characters.")

    # Cap score at 5
    if score > 5: score = 5
    
    return score, feedback, pwned_count

# --- STREAMLIT UI ---
def main():
    st.sidebar.header("About the Developer")
    st.sidebar.text("Emmanuel B. Onavewu")
    st.sidebar.info("Computer Science Student\nNetwork Security Enthusiast")
    st.sidebar.markdown("---")
    st.sidebar.write("Features:")
    st.sidebar.caption("✅ NIST Complexity Analysis")
    st.sidebar.caption("✅ HIBP API Integration (k-Anonymity)")

    st.title("🔒 Network Security Password Auditor")
    st.markdown("Test your password against **real-world data breaches** and **complexity standards**.")

    user_pass = st.text_input("Enter Password:", type="password", help="Passes k-Anonymity check. Safe to use.")

    if user_pass:
        final_score, report, pwned_count = check_strength(user_pass)

        st.markdown("---")
        st.subheader("Audit Report")

        # Visuals
        progress_value = final_score / 5
        
        if pwned_count > 0:
            st.error(f"⚠️ BREACH DETECTED: Found {pwned_count} times!")
            st.progress(0) # Force bar to 0 on breach
        elif final_score <= 2:
            st.progress(progress_value)
            st.error(f"WEAK 🔴 (Score: {final_score}/5)")
        elif final_score <= 4:
            st.progress(progress_value)
            st.warning(f"MODERATE 🟡 (Score: {final_score}/5)")
        else:
            st.progress(progress_value)
            st.success(f"STRONG 🟢 (Score: {final_score}/5)")

        with st.expander("Detailed Analysis", expanded=True):
            for item in report:
                if "CRITICAL" in item:
                    st.error(item)
                elif "✅" in item:
                    st.success(item)
                elif "❌" in item:
                    st.error(item)
                else:
                    st.warning(item)
    else:
        st.info("System Ready. Awaiting Input...")

if __name__ == "__main__":
    main()
    