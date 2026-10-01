import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 15
SALT = f"{VARIANT_NUMBER:05d}"
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    pass


def log_event(func):
    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        result_bool = False
        try:
            result_bool = func(username, password, *args, **kwargs)
            res_str = "success" if result_bool else "failure"
        except Exception:
            res_str = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": res_str,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []
                if os.path.exists(LOG_JSON_PATH):
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        try:
                            logs = json.load(f)
                        except json.JSONDecodeError:
                            logs = []

                logs.append(log_entry)
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=4)
            except OSError as err:
                print(f"[ПОМИЛКА ЛОГУВАННЯ]: {err}")

        return result_bool

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми!")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина пароля менша за мінімальну ({MIN_PASSWORD_LENGTH} символів)!"
        )

    salted_pwd = password + salt
    return hashlib.sha384(salted_pwd.encode("utf-8")).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    pwd_hash = generate_hash(password, salt=SALT)
    return username, pwd_hash


def create_users(users_list: list[tuple[str, str]], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "password_hash"])
        for user, pwd in users_list:
            u, h = create_user(user, pwd)
            writer.writerow([u, h])


def read_users_db(filepath: str) -> list[tuple[str, str]]:
    users_db = []
    with open(filepath, "r", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        next(reader, None)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
    return users_db


@log_event
def login(username: str, password: str, users_db: list[tuple[str, str]]) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими для входу!")

    try:
        input_hash = generate_hash(password, salt=SALT)
    except ValidationError:
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True

    return False


def run_task3() -> None:
    print("\nЗАВДАННЯ 3: Безпечне хешування (SHA-384), CSV-база та JSON-логування")

    users_to_register = (
        ("admin_user_07", "SuperSecurePassword2026!"),
        ("analyst_alex", "CryptoSafetyFirst!#99"),
        ("manager_serg", "ComplexP@ssw0rdForLab1"),
        ("engineer_dm", "CyberDefenseLevel4!Key"),
        ("tech_support", "SupportService#2026Pass"),
        ("auditor_ext", "AuditingSystemPassword77"),
        ("researcher_k", "QuantumSafePass!2026#"),
        ("operator_sec", "NetworkOperatorSecured99"),
        ("incident_lead", "IncidentResponseCommander1"),
        ("sys_admin_v7", "SystemAdministratorPass!77"),
    )

    try:
        print(f"\n1. Створення бази CSV ({USERS_CSV_PATH})...")
        create_users(users_to_register, USERS_CSV_PATH)
        print("   -> Базу даних успішно створено.")

        print("\n2. Читання CSV-бази даних:")
        users_db = read_users_db(USERS_CSV_PATH)
        print(f"{'Логін':<22} {'Хеш пароля (SHA-384)':<50}")
        for u, h in users_db:
            print(f"{u:<22} {h[:47]}...")

        print("\n3. Тестування автентифікації та логування у JSON:")
        res1 = login("admin_user_07", "SuperSecurePassword2026!", users_db)
        print(f" • Вхід admin_user_07 (коректний): {'УСПІШНО' if res1 else 'ВІДМОВА'}")

        res2 = login("admin_user_07", "WrongPassword12345!", users_db)
        print(f" • Вхід admin_user_07 (невірний): {'УСПІШНО' if res2 else 'ВІДМОВА'}")

    except OSError as file_err:
        print(f"[ФАЙЛОВА ПОМИЛКА]: {file_err}")
    except ValueError as val_err:
        print(f"[ПОМИЛКА ЗНАЧЕННЯ]: {val_err}")


if __name__ == "__main__":
    run_task3()
