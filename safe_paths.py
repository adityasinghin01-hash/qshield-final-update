"""POSIX descriptor-anchored paths for non-executing local scanners.

Only the explicitly selected target's parent is canonicalized. Descendants
must be opened relative to an already trusted directory descriptor, never
resolved through pathname aliases. Unsupported platforms fail closed.
"""
import os
from pathlib import Path


# Capture native API support before tests instrument os.open/stat for races.
_NATIVE_SUPPORT = (os.name == 'posix' and os.open in os.supports_dir_fd
                   and os.stat in os.supports_dir_fd
                   and os.stat in os.supports_follow_symlinks
                   and os.listdir in os.supports_fd)


def nofollow_supported():
    return _NATIVE_SUPPORT and all(getattr(os, flag, 0) for flag in
                                  ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'))


def selected_root(path):
    """Resolve authorized ancestry without resolving the selected leaf itself."""
    path = Path(os.path.abspath(path))
    return path.parent.resolve(strict=True) / path.name


def open_directory(path):
    """Open canonical absolute ancestors without following swapped symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise
