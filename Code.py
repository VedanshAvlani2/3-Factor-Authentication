import random
import smtplib
from email.mime.text import MIMEText
import hashlib
import serial
import webbrowser
import json
import stdiomask
from datetime import datetime
import re

users_file = "users.json"
log_file = "log_book.json"
admin_password = "12345"
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = ""
smtp_password = ""

security_questions = [
    "What is the name of your first school?",
    "What is your mother's name?",
    "In which city were you born?",
    "What is your first cars name?",
    "What is your favourite movie?",
    "What is the name of your first pet?"
]

def load_users():
    try:
        with open(users_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users_data):
    with open(users_file, "w") as file:
        json.dump(users_data, file, indent=4)

def log_activity(activity):
    with open(log_file, "a") as file:
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "activity": activity
        }
        file.write(json.dumps(log_entry) + "\n")

users = load_users()

arduino = serial.Serial('COM9', 9600)

def masked_input(prompt):
    return stdiomask.getpass(prompt)

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*()-_+=]", password):
        return False
    return True

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    print("                                                            Registration")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    admin_pass = masked_input("Enter Admin Password: ")
    if admin_pass != admin_password:
        print("Invalid Admin Password.")
        return False

    print("------------------------------------------------------------------------------------------------------------------------------------------")
    username = input("\nEnter a Username: ")
    if username in users:
        print("Username already exists. Please choose a different one.")
        return False

    while True:
        password = masked_input("Enter a Password: ")
        if not validate_password(password):
            print("Password must include at least 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        else:
            break

    print("\nSelect a Security Question:")
    for i, question in enumerate(security_questions, 1):
        print(f"{i}. {question}")

    choice = input("Enter the number corresponding to your chosen question: ")

    # Validate the user's choice
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(security_questions):
        print("Invalid choice.")
        return False

    security_question = security_questions[int(choice) - 1]
    security_answer = masked_input(f"Security Question: {security_question}\nAnswer: ")

    receiver_email = input("\nEnter your Email Address: ")
    rfid_uid = input("\nEnter RFID UID (comma-separated hex values without spaces): ").split(',')

    users[username] = {
        'password': hash_password(password),
        'security_question': security_question,
        'security_answer': hash_password(security_answer),
        'receiver_email': receiver_email,
        'rfid_uid': rfid_uid
    }

    print("\nRegistration successful!")
    print("------------------------------------------------------------------------------------------------------------------------------------------\n")
    log_activity(f"New user registered: {username}")
    return True

def send_email(receiver_email, subject, message_body):
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            message = MIMEText(message_body)
            message['Subject'] = subject
            message['From'] = smtp_username
            message['To'] = receiver_email
            server.sendmail(smtp_username, receiver_email, message.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def send_otp(receiver_email):
    otp = str(random.randint(100000, 999999))
    message = f"Welcome to the 3-Factor Authentication System\n\nYour OTP is: {otp}\n\nHave a Good Day!!!"
    subject = "Your OTP"
    if send_email(receiver_email, subject, message):
        return otp
    else:
        print("\nFailed to send OTP. Please try again later.")
        return None

def reset_password():
    print("\n                                                              Password Reset")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    admin_pass = masked_input("Enter Admin Password: ")
    if admin_pass != admin_password:
        print("Invalid Admin Password.")
        return

    username = input("Enter the Username: ")
    if username not in users:
        print("Username not found.")
        return

    security_answer = masked_input(users[username]['security_question'] + ": ")
    if hash_password(security_answer) != users[username]['security_answer']:
        print("Incorrect answer to security question. Access denied.")
        return

    new_password = ''
    while True:
        new_password = masked_input("Enter a New Password: ")
        if not validate_password(new_password):
            print("Password must include at least 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        else:
            break

    confirm_password = masked_input("Re-enter the New Password: ")
    print("Password Reset Successfully")
    if new_password != confirm_password:
        print("Passwords do not match.")
        return

    users[username]['password'] = hash_password(new_password)
    save_users(users)
    receiver_email = users[username]['receiver_email']
    message = f"Your password has been reset successfully. If you did not request this change, please contact support."
    subject = "Password Reset Alert"
    send_email(receiver_email, subject, message)
    log_activity(f"Password reset for user: {username}")

def delete_user():
    print("\n                                                               Delete User")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    admin_pass = masked_input("Enter Admin Password: ")
    if admin_pass != admin_password:
        print("Invalid Admin Password.")
        return

    username = input("Enter the Username to delete: ")
    if username not in users:
        print("Username not found.")
        return

    del users[username]
    save_users(users)
    print(f"User '{username}' deleted successfully.")

    log_activity(f"User '{username}' deleted by admin.")

def send_login_notification(username):
    receiver_email = users[username]['receiver_email']
    message = f"Your account was successfully logged in on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
    subject = "User Login Alert"
    send_email(receiver_email, subject, message)

def authenticate_user():
    print("\n                                                              First Stage")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    username = input("Enter your Username: ")
    if username not in users:
        print("Username does not exist.")
        return None

    password = masked_input("Enter your Password: ")
    hashed_password = hash_password(password)
    if hashed_password != users[username]['password']:
        print("Invalid Password.")
        return None

    return username

def verify_otp(stored_otp, receiver_email):
    print("\n                                                              Second Stage")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    print("-----------------------------------")
    print("| Email with OTP sent Successfully |")
    print("-----------------------------------")
    entered_otp = masked_input("Enter the OTP you received: ")
    
    if entered_otp == stored_otp:
        print("\nOTP Verified Successfully!")
        return True
    else:
        print("\nInvalid OTP. Authentication Failed.")
        return False

def verify_rfid(authenticated_username):
    print("\n                                                              Third Stage")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    print("\nPlace the RFID Card near the Reader")
    expected_uids = ''.join(users[authenticated_username]['rfid_uid']).upper()  

    while True:
        uid_line = arduino.readline().decode('utf-8').strip()
        
        if uid_line.startswith("Hello sir"):
            scanned_uid_hex = uid_line.split()[2:]

            scanned_uid = ''.join(scanned_uid_hex).upper()

            if scanned_uid == expected_uids:
                print("RFID recognized! Authentication Successful.")
                return True
            else:
                print("Invalid RFID card. Access denied.")
                return False
        else:
            print("Waiting for valid RFID card...")

def is_authorized_card(scanned_uid, expected_uids):
    for expected_uid in expected_uids:
        if scanned_uid == expected_uid:
            return True  
    return False 

def view_registered_users():
    print("\n\n                                                         Registered Users")
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    if users:
        print("Registered Usernames:")
        for username in users.keys():
            print("-", username)
    else:
        print("No Registered Users.")

def main():
    print("------------------------------------------------------------------------------------------------------------------------------------------")
    print("                                       Welcome to the 3-factor authentication system.")
    print("------------------------------------------------------------------------------------------------------------------------------------------")

    while True:
        print("\n1. Register a New User")
        print("2. Login")
        print("3. Reset Password")
        print("4. Delete User")
        print("5. View Registered Users")
        print("6. Exit")
        choice = input("Enter your Choice : ")
        print("------------------------------------------------------------------------------------------------------------------------------------------")

        if choice == '1':
            if register_user():
                save_users(users)
        elif choice == '2':
            authenticated_username = authenticate_user()
            if authenticated_username:
                print("\nAuthentication Successful! Proceed to the Second Stage.")
                stored_otp = send_otp(users[authenticated_username]['receiver_email'])
                if not verify_otp(stored_otp, users[authenticated_username]['receiver_email']):
                    print("\nAuthentication Failed.")
                    continue

                print("\nProceed to the Third Stage (RFID authentication).")
                if verify_rfid(authenticated_username):  
                    print("\n------------------------------------------------------------------------------------------------------------------------------------------")
                    print("   Congratulations! All stages of Authentication Passed Successfully.")
                    print("------------------------------------------------------------------------------------------------------------------------------------------")

                    send_login_notification(authenticated_username)
                    log_activity(f"User logged in: {authenticated_username}")

                    youtube_link = "https://youtu.be/dQw4w9WgXcQ?si=AdYOnQ2YgzT-FUj8"  
                    webbrowser.open(youtube_link)
                    break
                else:
                    print("\nAuthentication Failed.")
            else:
                print("\nAuthentication Failed.")
        elif choice == '3':
            reset_password()
        elif choice == '4':
            delete_user()
        elif choice == '5':
            view_registered_users()
        elif choice == '6':
            print("Exiting Program...")
            break
        else:
            print("Invalid Choice. Please enter a number from 1 to 6.")

if __name__ == '__main__':
    main()






















