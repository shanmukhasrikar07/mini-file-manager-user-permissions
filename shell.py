import sys
import os
import shlex
from auth import AuthManager
from intrusion import IntrusionDetector
from filesystem import FileSystemManager
from permissions import PermissionDeniedError

class Shell:
    def __init__(self):
        self.auth = AuthManager("users.json")
        self.detector = IntrusionDetector(self.auth, threshold_n=3, window_w=60, lock_time_t=120)
        self.fs = FileSystemManager("storage.json", "audit.log", intrusion_detector=self.detector)
        self.detector.audit_logger = self.fs.audit
        # Default active user: admin
        self.auth.current_user = self.auth.users.get("admin")

    def run(self):
        print("=" * 65)
        print("  Mini Unix File System Manager with RBAC, Intrusion & Versioning")
        print("  Type 'help' for command list or 'exit' to quit.")
        print("=" * 65)

        while True:
            try:
                user = self.auth.current_user
                if user:
                    # Check if locked out during active session
                    if user.is_locked():
                        rem = user.remaining_lock_time()
                        print(f"\nALERT: Account '{user.username}' is locked! Session terminated. ({rem}s remaining)")
                        self.auth.logout()
                        continue
                    prompt = f"#{user.username}:{self.fs.current_path}$ "
                else:
                    prompt = "#anonymous:/$ "

                cmd_line = input(prompt).strip()
                if not cmd_line:
                    continue

                if cmd_line.lower() in ["exit", "quit"]:
                    print("Exiting Mini File System. Goodbye!")
                    break

                self.execute_command(cmd_line)

            except (KeyboardInterrupt, EOFError):
                print("\nSession ended.")
                break
            except Exception as e:
                print(f"Error: {e}")

    def execute_command(self, cmd_line):
        try:
            parts = shlex.split(cmd_line)
        except ValueError as e:
            print(f"Syntax error: {e}")
            return

        cmd = parts[0]
        args = parts[1:]
        user = self.auth.current_user

        try:
            # Session & User Management
            if cmd == "login":
                if len(args) < 2:
                    print("Usage: login <username> <password>")
                    return
                u, msg = self.auth.authenticate(args[0], args[1], intrusion_detector=self.detector)
                print(msg)

            elif cmd == "logout":
                u = self.auth.logout()
                if u:
                    print(f"User '{u.username}' logged out.")
                else:
                    print("No active user session.")

            elif cmd == "whoami":
                if user:
                    print(f"User: {user.username} | Group: {user.group} | Role: {user.role}")
                else:
                    print("Not logged in.")

            elif cmd == "useradd":
                if not user or user.role != "admin":
                    print("Permission denied: Only administrators can create users.")
                    return
                if len(args) < 2:
                    print("Usage: useradd <username> <password> [group] [role]")
                    return
                uname = args[0]
                pwd = args[1]
                grp = args[2] if len(args) > 2 else "users"
                role = args[3] if len(args) > 3 else "standard"
                self.auth.create_user(uname, pwd, grp, role)
                print(f"User '{uname}' ({role}) created successfully.")

            # Directory & File Navigation
            elif cmd == "ls":
                path = args[0] if args else ""
                res = self.fs.ls(path, user)
                print(res)

            elif cmd == "cd":
                path = args[0] if args else "/"
                new_path = self.fs.cd(path, user)

            elif cmd == "pwd":
                print(self.fs.current_path)

            elif cmd == "mkdir":
                if not args:
                    print("Usage: mkdir <directory_path>")
                    return
                res = self.fs.mkdir(args[0], user)
                print(res)

            elif cmd == "touch":
                if not args:
                    print("Usage: touch <file_path>")
                    return
                res = self.fs.touch(args[0], user)
                print(res)

            elif cmd == "cat":
                if not args:
                    print("Usage: cat <file_path>")
                    return
                res = self.fs.cat(args[0], user)
                print(res)

            elif cmd == "write":
                if len(args) < 2:
                    print("Usage: write <file_path> <content>")
                    return
                path = args[0]
                content = " ".join(args[1:])
                res = self.fs.write(path, content, user)
                print(res)

            elif cmd == "chmod":
                if len(args) < 2:
                    print("Usage: chmod <octal_mode> <path> (e.g. chmod 750 /docs)")
                    return
                try:
                    mode = int(args[0], 8)
                except ValueError:
                    print("Invalid octal mode. Example: 750 or 640")
                    return
                res = self.fs.chmod(args[1], mode, user)
                print(res)

            elif cmd == "chown":
                if len(args) < 2:
                    print("Usage: chown <user>[:<group>] <path>")
                    return
                ug = args[0].split(":")
                new_u = ug[0]
                new_g = ug[1] if len(ug) > 1 else None
                res = self.fs.chown(args[1], new_u, new_g, user)
                print(res)

            elif cmd == "rm":
                if not args:
                    print("Usage: rm <path>")
                    return
                res = self.fs.rm(args[0], user)
                print(res)

            # Section X: Versioning Commands
            elif cmd == "history":
                if not args:
                    print("Usage: history <file_path>")
                    return
                node = self.fs.resolve_path(args[0], user)
                lines = self.fs.version_manager.get_history(node, user)
                print("\n".join(lines))

            elif cmd == "diff":
                if len(args) < 2:
                    print("Usage: diff <file_path> <v1> [v2]")
                    return
                node = self.fs.resolve_path(args[0], user)
                v1 = args[1]
                v2 = args[2] if len(args) > 2 else None
                diff_output = self.fs.version_manager.get_diff(node, user, v1, v2)
                print(diff_output)

            elif cmd == "restore":
                if len(args) < 2:
                    print("Usage: restore <file_path> <version_number>")
                    return
                node = self.fs.resolve_path(args[0], user)
                res = self.fs.version_manager.restore(node, user, args[1])
                self.fs.save_storage()
                self.fs.audit(user.username, "RESTORE", f"{args[0]} {args[1]}", "OK")
                print(res)

            # Section IX: Intrusion Detection & Lockout Admin Commands
            elif cmd == "alerts":
                if not user or user.role != "admin":
                    print("Permission denied: Only administrators can view security alerts.")
                    return
                alerts = self.detector.get_alerts(user)
                if not alerts:
                    print("No active security alerts.")
                else:
                    for a in alerts:
                        print(f"[{a['created_at']}] USER={a['username']:<8} REASON={a['reason']} (LOCKED UNTIL {a['until']})")

            elif cmd == "unlock":
                if len(args) < 1:
                    print("Usage: unlock <username>")
                    return
                if not user:
                    print("Permission denied: Login required.")
                    return
                success, msg = self.detector.unlock_user(args[0], user)
                print(msg)

            elif cmd == "help":
                self.print_help()

            else:
                print(f"Unknown command: '{cmd}'. Type 'help' for available commands.")

        except PermissionDeniedError as pe:
            print(pe)
        except Exception as e:
            print(f"Error: {e}")

    def print_help(self):
        print("\n--- Available Commands ---")
        print("  login <u> <p>          - Login as user")
        print("  logout                 - Logout current user")
        print("  whoami                 - Show active user identity")
        print("  useradd <u> <p> [role] - Create user (admin only)")
        print("  ls [path]              - List directory contents")
        print("  cd <path>              - Change working directory")
        print("  pwd                    - Print working directory")
        print("  mkdir <path>           - Create directory")
        print("  touch <path>           - Create empty file")
        print("  cat <path>             - Read file content")
        print("  write <path> <data>    - Overwrite file content (creates version snapshot)")
        print("  chmod <octal> <path>   - Change permission bits (owner/admin)")
        print("  chown <u>[:<g>] <path> - Change node owner (admin only)")
        print("  rm <path>              - Delete file or directory")
        print("  history <path>         - [Section X] List snapshots of file")
        print("  diff <path> <v1> [v2]  - [Section X] Compare file versions")
        print("  restore <path> <v>     - [Section X] Non-destructively rollback file")
        print("  alerts                 - [Section IX] View security alerts & locks (admin)")
        print("  unlock <user>          - [Section IX] Manually unlock account (admin)")
        print("  exit                   - Quit file system simulation\n")

if __name__ == "__main__":
    shell = Shell()
    shell.run()
