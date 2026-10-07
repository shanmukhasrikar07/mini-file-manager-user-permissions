import os
import json
import time
from models import Node
from permissions import require_permission, mode_to_string, READ, WRITE, EXECUTE, PermissionDeniedError
from versioning import VersionManager

class FileSystemManager:
    """
    Core File System Manager implementing the single centralized enforcement choke point.
    """
    def __init__(self, storage_file="storage.json", audit_file="audit.log", intrusion_detector=None):
        self.storage_file = storage_file
        self.audit_file = audit_file
        self.intrusion_detector = intrusion_detector
        self.version_manager = VersionManager(max_versions_k=5)
        self.root = None
        self.current_path = "/"
        self.load_storage()

    def audit(self, user, op, target, result="OK"):
        """Records timestamped audit entry."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] USER={user:<8} OP={op:<9} TARGET={target:<20} RESULT={result}\n"
        try:
            with open(self.audit_file, "a") as f:
                f.write(entry)
        except Exception:
            pass

    def _report_denial(self, user, target, kind="DENIED"):
        if self.intrusion_detector and user:
            locked, strikes = self.intrusion_detector.report_event(user.username, kind=kind)
            return locked, strikes
        return False, 0

    def resolve_path(self, path, user):
        """
        Resolves a path to a Node object while enforcing the EXECUTE (traverse) permission
        on every intermediate directory. If any directory lacks Execute, resolution stops
        and PermissionDeniedError is raised.
        """
        if not path:
            path = self.current_path

        # Normalize relative vs absolute paths
        if not path.startswith("/"):
            if self.current_path == "/":
                full_path = "/" + path
            else:
                full_path = self.current_path + "/" + path
        else:
            full_path = path

        parts = [p for p in full_path.split("/") if p]
        curr = self.root

        for idx, part in enumerate(parts):
            if part == ".":
                continue
            if part == "..":
                continue

            # Must have Execute permission to traverse into directory
            if curr.node_type == "dir":
                try:
                    require_permission(curr, user, EXECUTE, "traverse")
                except PermissionDeniedError:
                    self.audit(user.username if user else "anon", "TRAVERSE", curr.name, "DENIED")
                    locked, strikes = self._report_denial(user, curr.name, "TRAVERSE")
                    err_msg = f"Permission denied: /{part}"
                    if strikes > 0:
                        err_msg += f" ({strikes}/3)"
                    if locked:
                        err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
                    raise PermissionDeniedError(err_msg, path=curr.name)

            if part not in curr.children:
                raise FileNotFoundError(f"No such file or directory: '{part}'")
            curr = curr.children[part]

        return curr

    def mkdir(self, path, user, mode=0o755):
        parent_path, dir_name = self._split_parent(path)
        parent = self.resolve_path(parent_path, user)
        try:
            require_permission(parent, user, WRITE, "create directory")
        except PermissionDeniedError:
            self.audit(user.username, "MKDIR", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "MKDIR")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        if dir_name in parent.children:
            raise FileExistsError(f"Directory or file '{dir_name}' already exists.")

        new_dir = Node(name=dir_name, owner=user.username, group=user.group, permission=mode, node_type="dir")
        parent.children[dir_name] = new_dir
        self.save_storage()
        self.audit(user.username, "MKDIR", path, "OK")
        return f"Created directory '{dir_name}'"

    def touch(self, path, user, mode=0o644):
        parent_path, file_name = self._split_parent(path)
        parent = self.resolve_path(parent_path, user)
        try:
            require_permission(parent, user, WRITE, "create file")
        except PermissionDeniedError:
            self.audit(user.username, "TOUCH", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "TOUCH")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        if file_name in parent.children:
            return f"File '{file_name}' already exists."

        new_file = Node(name=file_name, owner=user.username, group=user.group, permission=mode, node_type="file")
        parent.children[file_name] = new_file
        self.save_storage()
        self.audit(user.username, "TOUCH", path, "OK")
        return f"Created file '{file_name}'"

    def write(self, path, data, user):
        """
        Writes data to a file. Enforces WRITE permission.
        Invokes VersionManager to snapshot existing content first (Section X).
        """
        parent_path, file_name = self._split_parent(path)
        try:
            node = self.resolve_path(path, user)
        except FileNotFoundError:
            # Create file if doesn't exist
            parent = self.resolve_path(parent_path, user)
            try:
                require_permission(parent, user, WRITE, "create file")
            except PermissionDeniedError:
                self.audit(user.username, "WRITE", path, "DENIED")
                locked, strikes = self._report_denial(user, path, "WRITE")
                err_msg = f"Permission denied: {path}"
                if strikes > 0:
                    err_msg += f" ({strikes}/3)"
                if locked:
                    err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
                raise PermissionDeniedError(err_msg)
            node = Node(name=file_name, owner=user.username, group=user.group, permission=0o644, node_type="file")
            parent.children[file_name] = node

        try:
            require_permission(node, user, WRITE, "write")
        except PermissionDeniedError:
            self.audit(user.username, "WRITE", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "WRITE")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        # Snapshot existing content if not empty (Section X)
        if node.content:
            snap = self.version_manager.snapshot(node, user)
            if snap:
                self.audit(user.username, "VERSION", f"{path} v{snap.num}", "OK")

        node.content = data
        self.save_storage()
        self.audit(user.username, "WRITE", path, "OK")
        return f"Wrote {len(data)} characters to '{node.name}'"

    def cat(self, path, user):
        """Reads file content. Enforces READ permission."""
        node = self.resolve_path(path, user)
        if node.node_type != "file":
            raise ValueError(f"'{node.name}' is a directory.")
        try:
            require_permission(node, user, READ, "read")
            self.audit(user.username, "READ", path, "OK")
            return node.content
        except PermissionDeniedError:
            self.audit(user.username, "READ", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "READ")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

    def ls(self, path, user):
        node = self.resolve_path(path if path else self.current_path, user)
        if node.node_type == "file":
            perm_str = mode_to_string(node.permission, is_dir=False)
            return f"{perm_str} {node.owner:<8} {node.group:<8} {len(node.content):<5} {node.name}"

        try:
            require_permission(node, user, READ, "list directory")
        except PermissionDeniedError:
            self.audit(user.username, "LS", path if path else self.current_path, "DENIED")
            locked, strikes = self._report_denial(user, path if path else self.current_path, "LS")
            err_msg = f"Permission denied: {path if path else self.current_path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        lines = []
        for name, child in sorted(node.children.items()):
            perm_str = mode_to_string(child.permission, is_dir=(child.node_type == "dir"))
            size = len(child.children) if child.node_type == "dir" else len(child.content or "")
            lines.append(f"{perm_str} {child.owner:<8} {child.group:<8} {size:<5} {name}")
        return "\n".join(lines) if lines else "(empty directory)"

    def cd(self, path, user):
        if not path or path == "/":
            self.current_path = "/"
            return "/"

        target_node = self.resolve_path(path, user)
        if target_node.node_type != "dir":
            raise ValueError(f"'{path}' is not a directory.")

        try:
            require_permission(target_node, user, EXECUTE, "traverse")
        except PermissionDeniedError:
            self.audit(user.username, "CD", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "CD")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        if path.startswith("/"):
            self.current_path = path
        else:
            if self.current_path == "/":
                self.current_path = "/" + path
            else:
                self.current_path = self.current_path + "/" + path
        return self.current_path

    def chmod(self, path, mode_octal, user):
        node = self.resolve_path(path, user)
        if user.role != "admin" and user.username != node.owner:
            raise PermissionError("Only the owner or administrator can change permissions.")

        node.permission = mode_octal
        self.save_storage()
        self.audit(user.username, "CHMOD", f"{path} {oct(mode_octal)}", "OK")
        return f"Permissions for '{node.name}' updated to {oct(mode_octal)}"

    def chown(self, path, new_owner, new_group, user):
        if user.role != "admin":
            raise PermissionError("Only administrators can change file ownership (chown).")

        node = self.resolve_path(path, user)
        node.owner = new_owner
        if new_group:
            node.group = new_group
        self.save_storage()
        self.audit(user.username, "CHOWN", f"{path} -> {new_owner}:{new_group}", "OK")
        return f"Ownership of '{node.name}' changed to {new_owner}"

    def rm(self, path, user):
        parent_path, name = self._split_parent(path)
        parent = self.resolve_path(parent_path, user)
        try:
            require_permission(parent, user, WRITE, "delete")
        except PermissionDeniedError:
            self.audit(user.username, "DELETE", path, "DENIED")
            locked, strikes = self._report_denial(user, path, "DELETE")
            err_msg = f"Permission denied: {path}"
            if strikes > 0:
                err_msg += f" ({strikes}/3)"
            if locked:
                err_msg += f"\nALERT: '{user.username}' locked for 120 s. Session ended."
            raise PermissionDeniedError(err_msg)

        if name not in parent.children:
            raise FileNotFoundError(f"'{name}' does not exist.")

        del parent.children[name]
        self.save_storage()
        self.audit(user.username, "DELETE", path, "OK")
        return f"Deleted '{name}'"

    def _split_parent(self, path):
        if not path or path == "/":
            raise ValueError("Invalid target path.")
        clean = path.strip("/")
        parts = clean.split("/")
        name = parts[-1]
        parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        return parent, name

    def load_storage(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    data = json.load(f)
                    self.root = Node.from_dict(data)
            except Exception:
                self._init_default_tree()
        else:
            self._init_default_tree()

    def _init_default_tree(self):
        self.root = Node(name="/", owner="admin", group="admin", permission=0o755, node_type="dir")
        docs = Node(name="docs", owner="admin", group="admin", permission=0o755, node_type="dir")
        self.root.children["docs"] = docs
        self.save_storage()

    def save_storage(self):
        if self.root:
            with open(self.storage_file, "w") as f:
                json.dump(self.root.to_dict(), f, indent=2)
