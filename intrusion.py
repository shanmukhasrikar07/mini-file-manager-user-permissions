import time
from collections import deque

class IntrusionDetector:
    """
    Section IX: Intrusion Detection and Automatic Account Lockout
    Policy: If a user generates N suspicious events within W seconds,
    the user is flagged, their session is terminated, and the account is locked for T seconds.
    """
    def __init__(self, auth_manager, threshold_n=3, window_w=60, lock_time_t=120, audit_logger=None):
        self.auth_manager = auth_manager
        self.threshold_n = threshold_n  # default N = 3
        self.window_w = window_w        # default W = 60 seconds
        self.lock_time_t = lock_time_t  # default T = 120 seconds
        self.audit_logger = audit_logger
        self.events = {}                # username -> deque of timestamps
        self.alerts_list = []           # list of alert records for admin review

    def report_event(self, username, kind="DENIED"):
        """
        Reports a suspicious security event (Permission Denial or Failed Login).
        Maintains a sliding-window queue of timestamps. Memory is strictly O(N) per user.
        """
        now = time.time()
        if username not in self.events:
            self.events[username] = deque()

        q = self.events[username]
        q.append(now)

        # Slide the window: remove timestamps older than W seconds
        while q and (now - q[0]) > self.window_w:
            q.popleft()

        strike_count = len(q)
        if self.audit_logger:
            self.audit_logger(username, kind, f"STRIKE {strike_count}/{self.threshold_n}", "DENIED")

        # Check threshold
        if strike_count >= self.threshold_n:
            self.trigger_lockout(username, now + self.lock_time_t)
            return True, strike_count

        return False, strike_count

    def trigger_lockout(self, username, until_timestamp):
        """
        Locks out user, terminates active session, clears queue, and records alert.
        """
        if username not in self.auth_manager.users:
            return

        user = self.auth_manager.users[username]
        # Admin is immune to lockout so recovery is never blocked
        if user.role == "admin":
            return

        user.locked_until = until_timestamp
        user.failed_count = 0
        self.auth_manager.save_users()

        # Terminate active session if user is currently logged in
        if self.auth_manager.current_user and self.auth_manager.current_user.username == username:
            self.auth_manager.logout()

        # Clear event queue after lock
        if username in self.events:
            self.events[username].clear()

        # Record alert
        lock_until_str = time.strftime("%H:%M:%S", time.localtime(until_timestamp))
        alert_entry = {
            "username": username,
            "reason": f"{self.threshold_n} denials / {self.window_w}s",
            "until": lock_until_str,
            "until_ts": until_timestamp,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.alerts_list.append(alert_entry)

        if self.audit_logger:
            self.audit_logger(username, "LOCK", f"locked for {self.lock_time_t}s until {lock_until_str}", "ALERT")

    def unlock_user(self, username, admin_user):
        """
        Admin command: unlock <user>
        Clears user lockout early and records an audit entry.
        """
        if admin_user.role != "admin":
            raise PermissionError("Only administrators can unlock accounts.")

        if username not in self.auth_manager.users:
            return False, f"User '{username}' not found."

        user = self.auth_manager.users[username]
        user.locked_until = None
        user.failed_count = 0
        self.auth_manager.save_users()

        if username in self.events:
            self.events[username].clear()

        if self.audit_logger:
            self.audit_logger(admin_user.username, "UNLOCK", username, "OK")

        return True, f"User '{username}' unlocked successfully."

    def get_alerts(self, admin_user):
        """
        Admin command: alerts
        Lists recent security flags and active locks.
        """
        if admin_user.role != "admin":
            raise PermissionError("Only administrators can view security alerts.")
        return self.alerts_list
