"""Run offline publication checks under one local process lock."""
import fcntl
import os
import stat
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    state = root / '.agent-state'
    state.mkdir(mode=0o700, exist_ok=True)
    if not stat.S_ISDIR(state.lstat().st_mode) or state.stat().st_mode & 0o077:
        raise ValueError('private state directory required')
    fd = os.open(str(state / 'checks.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another check is running; stopped.')
            return 2
        for command in ([sys.executable, '-B', '-m', 'unittest', '-q'],
                        ['git', 'diff', '--check'], ['git', 'diff', '--cached', '--check'],
                        [sys.executable, '-B', 'audit.py']):
            code = subprocess.run(command, cwd=root).returncode
            if code:
                print('CHECK FAILED: publication blocked')
                return code
    print('CHECKS PASSED: review staged scope and commit metadata before publishing.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError):
        print('CHECK ERROR: local checks unavailable', file=sys.stderr)
        sys.exit(2)
