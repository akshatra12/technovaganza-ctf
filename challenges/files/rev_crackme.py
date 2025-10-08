#!/usr/bin/env python3
"""
🔍 Python Reverse Engineering Challenge

I've created a simple password checker. Can you find the correct password?


Hint: Analyze the check_password function carefully.
The password follows a specific pattern.
"""

import hashlib

def obfuscate(data):
    """Simple obfuscation function"""
    result = []
    for i, char in enumerate(data):
        result.append(ord(char) ^ (i * 7 + 3) % 256)
    return result

def check_password(password):
    if len(password) != 16:
        print("❌ Incorrect length!")
        return False
    
    # Obfuscate the input
    obfuscated = obfuscate(password)
    
    # Expected obfuscated values
    expected = [49, 37, 19, 58, 38, 54, 89, 21, 44, 44, 31, 84, 44, 44, 9, 121]
    
    if obfuscated == expected:
        print("🎉 Access granted!")
        # Calculate flag from password
        flag_hash = hashlib.md5(password.encode()).hexdigest()[:8]
        print(f"Flag: Technovaganzactf{{{flag_hash}}}")
        return True
    else:
        print("❌ Access denied!")
        return False

if __name__ == "__main__":
    print("🔐 Password Checker v2.0")
    print("=" * 30)
    user_input = input("Enter password: ")
    check_password(user_input)