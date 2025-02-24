# 3-Factor Authentication System

## Overview
This project provides a **secure 3-factor authentication system** that ensures user authentication through:
1. **Password-based login**
2. **Email-based OTP verification**
3. **RFID card authentication**

It is designed for **high-security environments**, requiring multiple authentication steps before granting access.

## Features
- **User Registration & Management**: Allows new user registration with password and security question.
- **Secure Password Handling**: Uses **SHA-256 hashing** for password storage.
- **Multi-Factor Authentication**:
  - **First Stage**: Username & Password authentication
  - **Second Stage**: OTP verification via email
  - **Third Stage**: RFID card authentication
- **Admin Control**: Admin can reset passwords, delete users, and view registered users.
- **Activity Logging**: Logs authentication attempts and events.
- **Email Notifications**: Users receive email alerts upon successful login or password resets.

## Technologies Used
- **Python** (Core logic and authentication)
- **JSON** (User database management)
- **SMTP** (Email notifications & OTP handling)
- **Serial Communication** (Interfacing with RFID)
- **Secure Hashing** (SHA-256 for passwords)

## Setup Instructions
1. **Install Dependencies**:
   pip install pyserial stdiomask
   
2. **Configure Email SMTP**:
Update smtp_username and smtp_password with your email credentials.

3. **Connect RFID Reader**:
Update serial.Serial('COM9', 9600) with your RFID reader’s port.

4. **Run the Program**:
python Code.py

**Usage**
 - Register a new user
 - Login using password → OTP → RFID card
 - Admin can manage users (reset password, delete users, view logs)

**Future Enhancements**
 - Add biometric authentication as a fourth security factor.
 - Implement database integration instead of JSON for scalability.
