import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from shared.student import STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "incident_commander": {
        "role": "incident_response",
        "clearance": 4,
        "department": "CSIRT",
        "active": True,
    },
    "malware_analyst": {
        "role": "malware_researcher",
        "clearance": 3,
        "department": "Research",
        "active": True,
    },
    "monitoring_tech": {
        "role": "monitoring",
        "clearance": 2,
        "department": "NOC",
        "active": True,
    },
    "customer_rep": {
        "role": "customer_service",
        "clearance": 1,
        "department": "Customer",
        "active": True,
    },
    "backup_service": {
        "role": "service_account",
        "clearance": 2,
        "department": "System",
        "active": False,
    },
}

RESOURCES = [
    ("incident_playbook", 4),
    ("malware_lab", 3),
    ("monitoring_dashboards", 2),
    ("customer_portal", 1),
    ("emergency_procedures", 4),
    ("service_desk", 1),
    ("reverse_engineering", 3),
    ("alert_systems", 2),
    ("escalation_matrix", 3),
    ("knowledge_base", 1),
]

SECURITY_LEVELS = ("Public Access", "Authorized", "Privileged", "Critical")
BLOCKED_USERS = {"backup_service", "deactivated_svc", "policy_violation"}


def check_access(user_id: str, resource_level: int) -> tuple[str, str]:
    if user_id in BLOCKED_USERS:
        return "DENY", "User is blocked"

    if user_id not in USERS:
        return "DENY", "User not found"

    user_info = USERS[user_id]

    if not user_info.get("active", False):
        return "DENY", "Account inactive"

    if user_info.get("clearance", 0) >= resource_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def run_task2() -> None:
    print(f"Завдання 2 | Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}\n")

    print("Список ресурсів системи:")
    for res_name, level in RESOURCES:
        text_level = SECURITY_LEVELS[level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень безпеки: {text_level}")

    print("\nРезультати перевірки доступу:")
    all_check_users = list(USERS.keys()) + sorted(BLOCKED_USERS - set(USERS.keys()))

    for user in all_check_users:
        for res_name, res_level in RESOURCES:
            status, reason = check_access(user, res_level)
            reason_str = f" ({reason})" if reason else ""
            print(f"user={user} resource={res_name} -> {status}{reason_str}")


if __name__ == "__main__":
    run_task2()
