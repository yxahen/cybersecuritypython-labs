import random
import string
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "NetworkS3c!",
    "easy",
    "Firewa11@Pass",
    "anonymous",
    "Intrus10n#Detect",
    "sample",
    "Malwar3@Scan",
    "qwerty",
    "Vulnerab1l!ty",
    "common",
]

CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "easy",
    "anonymous",
    "sample",
    "qwerty",
    "common",
    "password",
}


def evaluate_password_strength(
    password: str,
    all_passwords: list[str],
    criteria: dict,
    forbidden: set[str],
) -> str:
    min_len = criteria["min_length"]

    if password in forbidden or len(password) < min_len:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    all_criteria_met = has_digit and has_upper and has_lower and has_special
    some_criteria_met = has_digit or has_upper or has_lower or has_special

    is_unique = all_passwords.count(password) == 1
    if all_criteria_met and len(password) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    if all_criteria_met and len(password) < min_len + 4:
        return "Сильний"

    if len(password) >= min_len and some_criteria_met:
        return "Середній"

    if some_criteria_met:
        return "Слабкий"

    return "Заборонений"


def run_task1() -> None:
    print(f"Завдання 1 | Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}")

    passwords_list = PASSWORDS.copy()

    random.seed(42)
    random_indices = [random.randint(0, len(passwords_list) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords_list.append(passwords_list[idx])

    print(f"{'№':<3} | {'Пароль':<20} | {'Оцінка надійності':<15}")

    for i, pwd in enumerate(passwords_list, 1):
        strength = evaluate_password_strength(
            pwd, passwords_list, CRITERIA, FORBIDDEN_PASSWORDS
        )
        print(f"{i:<3} | {pwd:<20} | {strength:<15}")


if __name__ == "__main__":
    run_task1()
