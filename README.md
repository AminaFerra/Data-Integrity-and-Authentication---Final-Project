# Mindful: Secure Health & Wellness Platform

## Overview
Mindful is a secure full-stack web application designed to handle sensitive health data and document workflows while maintaining robust data integrity, authentication, and encryption standards. It allows users to register securely, upload encrypted documents, track personal wellness data, and interact with healthcare providers through a secure digital environment.

Built using Flask and integrated with OAuth, 2FA, and SSL, Mindful simulates a real-world health and wellness support platform used in clinics, therapy centers, or corporate environments.

---

## Features

### Authentication & Access Control
- OAuth 2.0 login with GitHub and Okta
- Manual login with enforced password policies
- Two-Factor Authentication (2FA) via TOTP QR and Google Authenticator
- Session-based token authentication with expiration control
- Role-Based Access Control (RBAC) for Admin, Doctor, and Patient

### Secure Document Vault
- Upload and manage PDF, DOCX, and TXT documents
- AES encryption for secure file storage
- SHA-256 hashing to ensure data integrity
- HMAC verification on download
- Digital signature with signature validation

### Patient Wellness Monitoring
- Mood tracking visualized as wellness charts
- Logging doctor visits with review system
- Daily task/to-do management
- Real-time updates for doctors

### Admin Portal
- Admin: Add/edit/delete users, assign roles, and view full system logs

### Doctor portal
- Doctor: Monitor patient logs, prescribe treatments, and write reports

### HTTPS & Security Demonstrations
- SSL/TLS enabled using OpenSSL certificates
- Full HTTPS deployment
- Wireshark simulation of MITM attacks with encrypted vs unencrypted packet comparisons

---

## Technology Stack
- **Frontend**: HTML, CSS, Bootstrap
- **Backend**: Python Flask
- **Database**: SQLite + SQLAlchemy
- **Authentication**: OAuth2.0 (GitHub, Okta), 2FA (Google Authenticator)
- **Security**: OpenSSL, SHA-256, AES, HMAC, HTTPS

---

## System Requirements
- Python 3.10+
- Git
- pip
- OpenSSL

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/AminaFerra/Data-Integrity-and-Authentication---Final-Project.git
cd Data-Integrity-and-Authentication---Final-Project
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  
On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
(venv) pip install -r requirements.txt
```

### 4. Set Environment Variables
Create a `.env` file in the root directory:
```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key_here
```

### 5. Configure Local SSL
Generate SSL certificates:
```bash
 openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
```

### 6. Run the Application
```bash
(venv) $ python main.py
```
Then navigate to: `https://127.0.0.1:5000`

---

## Demonstrations & Testing
- **Manual & OAuth Login Testing**
- **2FA Integration with QR Code Scan & TOTP Verification**
- **File Upload Encryption & Signature Verification**
- **Wireshark MITM Testing with HTTPS vs HTTP**

---
## Team Members
- Yehia Ahmed Tawfiq – 2205126  
- Maryam Waheed Zamel – 2205154  
- Amina Ahmed Ferra – 2205225  
- Mayssoune Hussein Elmasry – 2205251  
- Hanin Mohamed Hamoda – 2205232

## License
This project is developed for academic purposes under the course "Data Integrity and Authentication" (Spring 2024–2025).

---