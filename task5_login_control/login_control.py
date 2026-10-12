"""Simulated login control with salted password hashing and temporary lockout."""

from dataclasses import dataclass
import argparse
import getpass
import hashlib
import hmac
import time


@dataclass
class LoginController:
    username: str
    password: str
    max_failures: int = 3
    lockout_seconds: float = 10.0
    clock: callable = time.monotonic

    def __post_init__(self) -> None:
        if self.max_failures < 1 or self.lockout_seconds < 0:
            raise ValueError("max_failures must be positive and lockout_seconds non-negative")
        self._salt = hashlib.sha256((self.username + ":salt").encode()).digest()[:16]
        self._password_hash = self._hash(self.password)
        self._failures = 0
        self._locked_until = 0.0

    def _hash(self, value: str) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", value.encode(), self._salt, 200_000)

    @property
    def locked(self) -> bool:
        return self.clock() < self._locked_until

    @property
    def failures(self) -> int:
        return self._failures

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        if self.locked:
            remaining = max(0, self._locked_until - self.clock())
            return False, f"locked; try again in {remaining:.1f}s"
        valid = hmac.compare_digest(username, self.username) and hmac.compare_digest(self._hash(password), self._password_hash)
        if valid:
            self._failures = 0
            return True, "login successful"
        self._failures += 1
        if self._failures >= self.max_failures:
            self._locked_until = self.clock() + self.lockout_seconds
            return False, f"too many failures; locked for {self.lockout_seconds:.1f}s"
        return False, f"invalid credentials ({self.max_failures - self._failures} attempt(s) remaining)"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local simulated login demo.")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="correct-horse-battery-staple")
    args = parser.parse_args()
    system = LoginController(args.username, args.password)
    print(f"Demo account: {args.username} (password is supplied by the command line for repeatability)")
    for _ in range(system.max_failures):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        ok, message = system.authenticate(username, password)
        print(message)
        if ok:
            break


if __name__ == "__main__":
    main()
