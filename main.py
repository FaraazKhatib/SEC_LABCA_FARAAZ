import re
import bcrypt
import logging
import time
import json

#LOGGING SETUP 

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(message)s"
)

#DATABASE (Mock)

users_db = {}
login_attempts = {}

#1. INPUT VALIDATION

def validate_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,20}", username))


def validate_password(password):
    return bool(re.fullmatch(
        r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}", password
    ))

#2. ATTACK DETECTION

def detect_attack(text):
    patterns = [
        r"<.*?>",                 # HTML tags (XSS)
        r"(onerror|onload)",     # JS events
        r"('|\"|\s)(OR|AND)\s",  # SQL injection logic
        r";", r"--"
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

#3. PASSWORD SECURITY

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

#4. ACCOUNT LOCKOUT

MAX_ATTEMPTS = 5
LOCK_TIME = 60  

def is_locked(username):
    if username in login_attempts:
        attempts, last_time = login_attempts[username]

        if attempts >= MAX_ATTEMPTS:
            if time.time() - last_time < LOCK_TIME:
                return True
            else:
                # reset after lock period
                login_attempts[username] = [0, 0]
    return False


def record_failed_attempt(username):
    if username not in login_attempts:
        login_attempts[username] = [1, time.time()]
    else:
        login_attempts[username][0] += 1
        login_attempts[username][1] = time.time()

# LOGGING HELPER

def log_event(event_type, data):
    log_entry = {
        "event": event_type,
        "data": data,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    logging.info(json.dumps(log_entry))

# REGISTER

def register():
    try:
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Attack detection
        if detect_attack(username) or detect_attack(password):
            print("Malicious input detected!")
            log_event("attack_register", {"username": username})
            return

        # Input validation
        if not validate_username(username):
            print("Invalid username! Use 3–20 chars (letters, numbers, _)")
            return

        if not validate_password(password):
            print("Weak password! Must include upper, lower, digit, special char")
            return

        # Check existing user
        if username in users_db:
            print("User already exists")
            return

        # Store hashed password
        users_db[username] = hash_password(password)

        log_event("register_success", {"username": username})
        print("Registration successful!")

    except Exception as e:
        logging.error(json.dumps({"event": "register_error", "error": str(e)}))
        print("Something went wrong!")

# LOGIN

def login():
    try:
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Attack detection (FIXED)
        if detect_attack(username) or detect_attack(password):
            print("Malicious input detected!")
            log_event("attack_login", {"username": username})
            return

        # Lock check
        if is_locked(username):
            print("Account locked. Try again later.")
            log_event("account_locked", {"username": username})
            return

        # Fail-safe default
        if username not in users_db:
            print("Invalid credentials")
            return

        # Password verification
        if verify_password(password, users_db[username]):
            print("Login successful!")
            login_attempts[username] = [0, 0]  # reset attempts
            log_event("login_success", {"username": username})
        else:
            print("Invalid credentials")
            record_failed_attempt(username)
            log_event("login_failed", {"username": username})

    except Exception as e:
        logging.error(json.dumps({"event": "login_error", "error": str(e)}))
        print("Something went wrong!")



def main():
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid option")



if __name__ == "__main__":
    main()