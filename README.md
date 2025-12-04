# CyberVault-Flask

A simple, secure, and modern-looking password vault application built using **Flask**, **SQLAlchemy**, and **Bootstrap 5**, focusing on core security concepts like password hashing, data encryption, and an advanced steganography utility.

## ✨ Features

* **User Authentication:** Secure user registration and login using `werkzeug.security` (scrypt hashing).
* **Password Vault:** Users can securely store their credentials.
    * Data is encrypted using **Fernet** (symmetric encryption) before being saved to the database.
    * Built-in **Password Strength Validator** for user-provided passwords.
    * **Password Generator** for creating strong, random passwords.
* **Steganography Tool:** A dedicated section for hiding and revealing sensitive credentials within image files (PNG/JPG) using a simple LSB (Least Significant Bit) technique.
* **Modern UI:** A 'cyber' themed user interface styled with custom CSS and Bootstrap 5.

## ⚙️ Technical Details

### Backend
* **Framework:** Flask
* **Database:** SQLAlchemy (SQLite for development)
* **Authentication:** `flask-login`, `werkzeug.security` (scrypt)
* **Encryption:** `cryptography.fernet`
* **Image Manipulation:** Pillow (PIL) for steganography logic

### Frontend
* HTML/Jinja2 templates (`base.html`, `login.html`, `dashboard.html`, `stego.html`)
* Bootstrap 5 for responsive layout.
* Custom CSS (`style.css`) for the dark/neon theme.
* JavaScript for password strength check, password generation, and password show/hide functionality.

## 🚀 Getting Started

### Prerequisites

1.  Python 3.x
2.  `pip` (Python package installer)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/CyberVault-Flask.git](https://github.com/YourUsername/CyberVault-Flask.git)
    cd CyberVault-Flask
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt 
    # (Assuming you create a requirements.txt with flask, flask-sqlalchemy, flask-login, 
    # werkzeug, cryptography, Pillow)
    ```
    *If you don't have a `requirements.txt`, install them manually:*
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Werkzeug cryptography Pillow
    ```

3.  **Run the application:**
    ```bash
    python app.py
    ```

4.  **Access the application:**
    Open your browser and navigate to `http://127.0.0.1:5000/`.

## ⚠️ Security Notes (Important for Production)

* **Encryption Key:** The current `app.py` uses a single hardcoded key (`Fernet.generate_key()`) that is generated on every run if you don't persist it. **This is for demonstration only.** In a real-world application, each user should have a unique encryption key derived from a secure, high-entropy master password or another unique secret, and this key must be securely stored and managed.
* **LSB Steganography:** LSB steganography is easily detectable and reversible. It is presented here as a concept demonstration rather than a production-grade security feature.

## 🤝 Contributing

This project is a starting point for learning about web security in Python. Feel free to fork the repository and improve the code!
