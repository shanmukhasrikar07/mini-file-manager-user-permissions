import hashlib
import os
import json
import time

class User:
    def __init__(self, username, password_hash, salt, group="users", role="standard", failed_count=0, locked_until=None):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.group = group
        self.role = role  # 'admin' or 'standard'
        self.failed_count = failed_count
        self.locked_until = locked_until  # timestamp (float/int) or None

    def is_locked(self):
        if self.locked_until is None:
            return False
        if time.time() < self.locked_until:
            return True
        # Lock expired
        self.locked_until = None
        self.failed_count = 0
        return False

    def remaining_lock_time(self):
        if self.locked_until and time.time() < self.locked_until:
            return int(self.locked_until - time.time())
        return 0

    def to_dict(self):
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "salt": self.salt,
            "group": self.group,
            "role": self.role,
            "failed_count": self.failed_count,
            "locked_until": self.locked_until
        }

    @staticmethod
    def from_dict(data):
        return User(
            username=data["username"],
            password_hash=data["password_hash"],
            salt=data["salt"],
            group=data.get("group", "users"),
            role=data.get("role", "standard"),
            failed_count=data.get("failed_count", 0),
            locked_until=data.get("locked_until", None)
        )

class AuthManager:
    def __init__(self, users_file="users.json"):
        self.users_file = users_file
        self.users = {}
        self.current_user = None
        self.load_users()

    def _hash_password(self, password, salt):
        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

    def create_user(self, username, password, group="users", role="standard"):
        if username in self.users:
            raise ValueError(f"User '{username}' already exists.")
        salt = os.urandom(16).hex()
        pwd_hash = self._hash_password(password, salt)
        user = User(username, pwd_hash, salt, group, role)
        self.users[username] = user
        self.save_users()
        return user

    def authenticate(self, username, password, intrusion_detector=None):
        if username not in self.users:
            if intrusion_detector:
                intrusion_detector.report_event(username, "LOGIN_UNKNOWN_USER")
            return None, "Invalid username or password."

        user = self.users[username]

        # Check Lockout BEFORE password verification
        if user.is_locked():
            rem = user.remaining_lock_time()
            return None, f"Account locked. Try again in {rem} s."

        # Verify password
        pwd_hash = self._hash_password(password, user.salt)
        if pwd_hash == user.password_hash:
            user.failed_count = 0
            self.current_user = user
            self.save_users()
            return user, "Login successful."
        else:
            user.failed_count += 1
            if intrusion_detector:
                intrusion_detector.report_event(username, "LOGIN_FAILED")
            self.save_users()
            return None, "Invalid username or password."

    def logout(self):
        u = self.current_user
        self.current_user = None
        return u

    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, "r") as f:
                    data = json.load(f)
                    self.users = {uname: User.from_dict(udata) for uname, udata in data.items()}
            except Exception:
                self._init_default_admin()
        else:
            self._init_default_admin()

    def _init_default_admin(self):
        self.users = {}
        self.create_user("admin", "admin123", group="admin", role="admin")
        self.create_user("alice", "pass123", group="users", role="standard")
        self.create_user("bob", "bobpass", group="guest", role="standard")

    def save_users(self):
        with open(self.users_file, "w") as f:
            json.dump({uname: u.to_dict() for uname, u in self.users.items()}, f, indent=2)
