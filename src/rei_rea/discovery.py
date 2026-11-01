"""Fresh, read-only executable discovery; never starts a process."""
from __future__ import annotations

import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor


def _windows_names() -> set[str] | None:
    """Prefilter absent names with one directory scan, not thousands of stats.

    Include cwd conservatively; shutil.which retains authority over PATHEXT,
    precedence and whether the current directory is permitted on this Python.
    No results survive a discovery request.
    """
    names: set[str] = set()
    directories = dict.fromkeys([os.curdir, *os.environ.get("PATH", "").split(os.pathsep)])
    for directory in directories:
        try:
            with os.scandir(directory or os.curdir) as entries:
                for entry in entries:
                    name = entry.name.casefold()
                    names.add(name)
                    for index, char in enumerate(name):
                        if char == '.':
                            names.add(name[:index])
        except PermissionError:
            # A known file may be searchable even if directory listing is denied.
            return None
        except OSError:
            continue
    return names


def resolve_executables(executables) -> dict[str, str | None]:
    """Return PATH evidence, never an installation or capability assertion."""
    candidates = _windows_names() if sys.platform == "win32" else None
    unique = list(dict.fromkeys(executables))
    if sys.platform == "win32" and candidates is None:
        # Restricted directory listing: preserve which() semantics while bounding
        # concurrent metadata probes. This is an I/O budget, not a tool ceiling.
        with ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(unique, pool.map(shutil.which, unique)))
    return {
        name: shutil.which(name) if (
            candidates is None or os.path.dirname(name) or name.casefold() in candidates
        ) else None
        for name in unique
    }
