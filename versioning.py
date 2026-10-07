import hashlib
import time
import difflib
from models import Version
from permissions import require_permission, READ, WRITE

class VersionManager:
    """
    Section X: File Versioning and Rollback
    - Automatically snapshots previous content on overwrite.
    - Keeps at most K (default 5) versions with FIFO eviction.
    - Enforces SHA-256 cryptographic integrity.
    - Rollbacks are non-destructive (current content is snapshotted before restore).
    """
    def __init__(self, max_versions_k=5):
        self.max_versions_k = max_versions_k

    def snapshot(self, node, acting_user):
        """
        Creates a new immutable snapshot of the file's current content.
        Bounded at K=5 versions using FIFO eviction.
        """
        if node.node_type != "file":
            return

        # Do not snapshot if file is currently completely empty
        if node.content == "" or node.content is None:
            return

        if node.versions is None:
            node.versions = []

        # Determine next version number
        next_num = 1 if not node.versions else node.versions[-1].num + 1
        ts = time.strftime("%H:%M:%S")
        content_hash = hashlib.sha256(node.content.encode('utf-8')).hexdigest()

        version_obj = Version(
            num=next_num,
            timestamp=ts,
            by=acting_user.username if acting_user else "system",
            content=node.content,
            sha=content_hash
        )
        node.versions.append(version_obj)

        # FIFO eviction if cap exceeded
        if len(node.versions) > self.max_versions_k:
            node.versions.pop(0)

        return version_obj

    def get_history(self, node, user):
        """
        Command: history <path>
        Lists all available snapshots for the given file. Requires READ permission.
        """
        require_permission(node, user, READ, "read history")
        if node.node_type != "file":
            raise ValueError(f"'{node.name}' is a directory, not a file.")

        history_lines = []
        if node.versions:
            for v in node.versions:
                preview = (v.content[:25] + '...') if len(v.content) > 25 else v.content
                preview_clean = preview.replace('\n', ' ')
                history_lines.append(f"v{v.num:<2} {v.by:<8} {v.timestamp} \"{preview_clean}\" (SHA: {v.sha[:8]})")
        
        curr_preview = (node.content[:25] + '...') if len(node.content) > 25 else node.content
        curr_clean = curr_preview.replace('\n', ' ')
        history_lines.append(f"(current)       \"{curr_clean}\"")
        return history_lines

    def get_diff(self, node, user, v1_str, v2_str=None):
        """
        Command: diff <path> <v1> [v2]
        Shows line-level differences between two versions, or a version and current content. Requires READ.
        """
        require_permission(node, user, READ, "diff versions")
        if node.node_type != "file":
            raise ValueError(f"'{node.name}' is a directory.")

        content1 = self._get_version_content(node, v1_str)
        content2 = node.content if (v2_str is None or v2_str.lower() == "current") else self._get_version_content(node, v2_str)

        lines1 = content1.splitlines(keepends=True)
        lines2 = content2.splitlines(keepends=True)

        diff = difflib.unified_diff(
            lines1, lines2,
            fromfile=f"{node.name} (v{v1_str})",
            tofile=f"{node.name} ({'current' if v2_str is None else 'v' + v2_str})",
            lineterm=""
        )
        diff_text = "".join(diff)
        return diff_text if diff_text else "No differences found."

    def _get_version_content(self, node, v_str):
        if not node.versions:
            raise ValueError(f"No version history found for '{node.name}'.")
        try:
            num = int(v_str.replace("v", ""))
        except ValueError:
            raise ValueError(f"Invalid version identifier: '{v_str}'.")

        for v in node.versions:
            if v.num == num:
                # Cryptographic SHA-256 verification
                calc_hash = hashlib.sha256(v.content.encode('utf-8')).hexdigest()
                if calc_hash != v.sha:
                    raise IntegrityError(f"Corrupted snapshot: SHA-256 mismatch on version {num}!")
                return v.content
        raise ValueError(f"Version v{num} not found for '{node.name}'.")

    def restore(self, node, user, v_str):
        """
        Command: restore <path> <v>
        Rolls back to an earlier version.
        Restoration is NON-DESTRUCTIVE: current content is snapshotted as a new version before restore.
        Requires WRITE permission on the file.
        """
        require_permission(node, user, WRITE, "restore version")
        if node.node_type != "file":
            raise ValueError(f"'{node.name}' is a directory.")

        target_content = self._get_version_content(node, v_str)

        # Snapshot current content first (NON-DESTRUCTIVE)
        new_snap = self.snapshot(node, user)
        snap_msg = f"Previous content saved as v{new_snap.num}." if new_snap else ""

        # Apply target version
        node.content = target_content
        return f"Restored {v_str}. {snap_msg}"

class IntegrityError(Exception):
    pass
