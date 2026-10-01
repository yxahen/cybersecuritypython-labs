import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

PBKDF2_ITERATIONS: int = 100_000
EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
        password: str | None = None,
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email: str = ""
        self.email = email

        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

        if password:
            self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'.")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        calc_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, calc_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', status='{status}')"


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        password: str | None = None,
        permissions: set[str] | None = None,
    ) -> None:
        super().__init__(username, email, role, active, password)
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"Admin({base_str}, permissions=[{perms}])"


class Session:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Значення timeout_sec має бути додатним.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity).total_seconds() < timeout_sec


@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self) -> None:
        self.logs: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.logs.append(entry)

    def show_all(self) -> list[AuditEntry]:
        return self.logs


class UserAccount:
    SESSION_TIMEOUT_SEC: int = 900

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        username = self.user.username
        self.session = None
        self.audit_log.add_log(username, "logout")

    def __getitem__(self, key: str):
        allowed = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if key not in allowed:
            raise KeyError(f"Невірний ключ або обмежено доступ: '{key}'")
        return allowed[key]

    def __setitem__(self, key: str, value) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути екземпляром User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення для 'session' має бути Session або None.")
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення для 'audit_log' має бути AuditLog.")
            self.audit_log = value
        else:
            raise KeyError(f"Невірний ключ або заборонено запис: '{key}'")


def run_demo() -> None:
    print("=== Демонстрація Завдання 1: Модель користувача та безпеки ===")

    admin_user = Admin(
        username="sysadmin",
        email="admin.root@company.corp",
        password="SuperStrongPassword123!",
        permissions={"read_logs", "manage_users"},
    )
    print(f"[+] Створено адміна: {admin_user}")

    admin_user.grant_permission("system_reboot")
    print(
        f"[+] Надано право 'system_reboot': {admin_user.has_permission('system_reboot')}"
    )
    admin_user.revoke_permission("manage_users")
    print(f"[+] Оновлений адмін: {admin_user}")

    try:
        admin_user.email = "bad_email_format.com"
    except ValueError as e:
        print(f"[!] Очікувана помилка при зміні email: {e}")

    account = UserAccount(user=admin_user)

    failed = account.login("sysadmin", "WrongPassword", "192.168.1.50")
    print(
        f"[+] Спроба входу з невірним паролем: {failed} (Auth: {account.is_authenticated()})"
    )

    success = account.login("sysadmin", "SuperStrongPassword123!", "192.168.1.50")
    print(
        f"[+] Спроба входу з вірним паролем: {success} (Auth: {account.is_authenticated()})"
    )

    curr_user: User = account["user"]
    print(f"[+] Отримано користувача через account['user']: {curr_user.username}")

    account.logout()
    print(f"[+] Стан авторизації після logout: {account.is_authenticated()}")

    print("\n--- Записи AuditLog ---")
    log_box: AuditLog = account["audit_log"]
    for entry in log_box.show_all():
        print(
            f"[{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] User: {entry.username} -> Action: {entry.action}"
        )
