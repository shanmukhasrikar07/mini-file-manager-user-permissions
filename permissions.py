# Unix Permission Constants
READ = 4     # 'r' - 100
WRITE = 2    # 'w' - 010
EXECUTE = 1  # 'x' - 001

class PermissionDeniedError(Exception):
    def __init__(self, message, path=""):
        super().__init__(message)
        self.path = path

def has_permission(node, user, requested_bit):
    """
    Evaluates Unix 9-bit discretionary access control in O(1) time.
    Administrators bypass all checks unconditionally.
    """
    if user.role == "admin":
        return True

    # Determine class: owner, group, or other
    if user.username == node.owner:
        cls = 'owner'
    elif user.group == node.group:
        cls = 'group'
    else:
        cls = 'other'

    shift = {'owner': 6, 'group': 3, 'other': 0}[cls]
    bits = (node.permission >> shift) & 0o7
    return (bits & requested_bit) == requested_bit

def require_permission(node, user, requested_bit, op_name="access"):
    """
    Enforces permission check. Raises PermissionDeniedError if unauthorized.
    """
    if not has_permission(node, user, requested_bit):
        raise PermissionDeniedError(f"Permission denied: {node.name} (requires {op_name})", path=node.name)

def mode_to_string(mode, is_dir=False):
    """Converts 9-bit octal integer into standard 'rwxr-xr-x' string representation."""
    type_char = 'd' if is_dir else '-'
    res = []
    for shift in [6, 3, 0]:
        bits = (mode >> shift) & 0o7
        res.append('r' if bits & READ else '-')
        res.append('w' if bits & WRITE else '-')
        res.append('x' if bits & EXECUTE else '-')
    return type_char + ''.join(res)
