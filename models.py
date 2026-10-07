import hashlib
import time
import json

class Version:
    def __init__(self, num, timestamp, by, content, sha=None):
        self.num = num
        self.timestamp = timestamp
        self.by = by
        self.content = content
        self.sha = sha if sha else hashlib.sha256(content.encode('utf-8')).hexdigest()

    def to_dict(self):
        return {
            "num": self.num,
            "timestamp": self.timestamp,
            "by": self.by,
            "content": self.content,
            "sha": self.sha
        }

    @staticmethod
    def from_dict(data):
        return Version(
            num=data["num"],
            timestamp=data["timestamp"],
            by=data["by"],
            content=data["content"],
            sha=data["sha"]
        )

class Node:
    def __init__(self, name, owner, group, permission=0o750, node_type="file"):
        self.name = name
        self.owner = owner
        self.group = group
        self.permission = permission  # 9-bit octal integer
        self.node_type = node_type    # 'file' or 'dir'
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.children = {} if node_type == "dir" else None
        self.content = "" if node_type == "file" else None
        self.versions = [] if node_type == "file" else None  # List of Version objects

    def to_dict(self):
        d = {
            "name": self.name,
            "owner": self.owner,
            "group": self.group,
            "permission": oct(self.permission),
            "node_type": self.node_type,
            "created_at": self.created_at
        }
        if self.node_type == "dir":
            d["children"] = {k: v.to_dict() for k, v in self.children.items()}
        else:
            d["content"] = self.content
            d["versions"] = [v.to_dict() for v in self.versions] if self.versions else []
        return d

    @staticmethod
    def from_dict(data):
        perm = int(data["permission"], 8) if isinstance(data["permission"], str) else data["permission"]
        node = Node(
            name=data["name"],
            owner=data["owner"],
            group=data["group"],
            permission=perm,
            node_type=data["node_type"]
        )
        node.created_at = data.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S"))
        if node.node_type == "dir":
            node.children = {k: Node.from_dict(v) for k, v in data.get("children", {}).items()}
        else:
            node.content = data.get("content", "")
            node.versions = [Version.from_dict(v) for v in data.get("versions", [])]
        return node
