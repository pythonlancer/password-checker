# 🔐 Python Password Breach Checker

A simple Python tool that checks whether a password has ever been exposed in public data breaches using the Have I Been Pwned API.

This project demonstrates secure API usage, hashing, and the k-Anonymity model to protect user privacy.

---

## 🚀 Features

- Checks passwords against real-world breach data
- Uses SHA-1 hashing for security
- Implements k-Anonymity (your full password is never sent)
- Supports checking multiple passwords via CLI
- Lightweight and easy to use

---

## 🛠 Technologies Used

- `requests`
- `hashlib`
- `sys`
- Have I Been Pwned Pwned Passwords API

---

## 🔍 How It Works

1. The password is hashed locally using SHA-1.
2. Only the first 5 characters of the hash are sent to the API.
3. The API returns matching hash suffixes.
4. The script compares them locally.
5. If a match is found, it returns how many times the password appeared in breaches.

This method follows the k-Anonymity model, meaning your full password hash never leaves your machine.

---

## 💪 Password Strength Checker

In addition to checking whether a password has been exposed in data breaches, this project can also evaluate how strong a password is based on common security best practices.

The strength check analyzes:

- Minimum length (8+ characters recommended)
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Overall complexity

---

### 🔎 Strength Criteria

A strong password should:

- Be at least **12 characters long**
- Include **uppercase and lowercase letters**
- Contain **numbers**
- Include **special characters** (e.g., !@#$%^&*)
- Avoid common patterns (e.g., `123456`, `password`, `qwerty`)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/pythonlancer/password-checker.git
cd password-checker