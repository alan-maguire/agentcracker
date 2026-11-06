"""Drive a program on a pseudo-terminal with a tiny expect-like script.

usage: pty.py [--timeout SECS] [--rows R --cols C] -- PROGRAM ARGS... < SCRIPT

SCRIPT has one command per line (blank lines and #comments are ignored):

  expect REGEX     wait until REGEX (Python syntax) appears in the output
                   produced since the previous expect matched
  send TEXT        write TEXT; backslash escapes are honoured (\\r, \\x03, ...)
  key C            send C followed by \\r (answers the line-based prompts)
  sleep SECS       pause, still collecting output
  resize R C       set the terminal size and send SIGWINCH to the program
  eof              close the terminal's input side (send ^D)

After the script runs the program is waited for (up to --timeout).  The
transcript (with ANSI escapes stripped) goes to stdout; the exit status is the
program's, 124 if a step or the program timed out, 125 on script errors.
"""

import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\r")


def main():
    args = sys.argv[1:]
    timeout, rows, cols = 60.0, 40, 120
    while args and args[0] != "--":
        a = args.pop(0)
        if a == "--timeout":
            timeout = float(args.pop(0))
        elif a == "--rows":
            rows = int(args.pop(0))
        elif a == "--cols":
            cols = int(args.pop(0))
        else:
            sys.exit(f"pty.py: unknown option {a}")
    if not args:
        sys.exit("pty.py: missing -- PROGRAM")
    prog = args[1:]
    script = [l.rstrip("\n") for l in sys.stdin if l.strip() and not l.lstrip().startswith("#")]

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(prog[0], prog)

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    out = bytearray()
    mark = 0  # expect searches the stripped transcript from here
    alive = True

    def pump(t):
        nonlocal alive
        end = time.time() + t
        while alive:
            left = end - time.time()
            if left <= 0:
                return
            r, _, _ = select.select([fd], [], [], min(left, 0.05))
            if r:
                try:
                    d = os.read(fd, 65536)
                except OSError:
                    d = b""
                if not d:
                    alive = False
                    return
                out.extend(d)

    def text(b):
        return ANSI.sub(b"", bytes(b)).decode(errors="replace")

    def finish(code, why=None):
        sys.stdout.write(text(out))
        if why:
            sys.stdout.write(f"\n[pty.py: {why}]\n")
        sys.stdout.flush()
        if code != 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        sys.exit(code)

    pump(0.2)
    for line in script:
        cmd, _, arg = line.strip().partition(" ")
        if cmd == "expect":
            rx = re.compile(arg.encode())
            end = time.time() + timeout
            while True:
                # mark is an offset into the escape-stripped transcript
                m = rx.search(ANSI.sub(b"", bytes(out)), mark)
                if m:
                    mark = m.end()
                    break
                if not alive or time.time() > end:
                    finish(124, f"timed out waiting for /{arg}/")
                pump(0.1)
        elif cmd in ("send", "key"):
            data = arg.encode().decode("unicode_escape").encode("latin-1")
            if cmd == "key":
                data += b"\r"
            os.write(fd, data)
            pump(0.1)
        elif cmd == "sleep":
            pump(float(arg))
        elif cmd == "resize":
            r, c = arg.split()
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", int(r), int(c), 0, 0))
            os.kill(pid, signal.SIGWINCH)
            pump(0.2)
        elif cmd == "eof":
            os.write(fd, b"\x04")
            pump(0.1)
        else:
            finish(125, f"bad script line: {line}")

    end = time.time() + timeout
    while alive and time.time() < end:
        pump(0.2)
        try:
            p, st = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if p:
            pump(0.2)
            sys.stdout.write(text(out))
            sys.exit(os.waitstatus_to_exitcode(st))
    try:
        p, st = os.waitpid(pid, 0 if not alive else os.WNOHANG)
    except ChildProcessError:
        p, st = 0, 0
    if p:
        sys.stdout.write(text(out))
        sys.exit(os.waitstatus_to_exitcode(st))
    finish(124, "program did not exit")


if __name__ == "__main__":
    main()
