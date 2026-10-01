import argparse
import csv
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_logging(log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        handlers=handlers,
    )


def is_off_hours(dt: datetime) -> bool:
    if dt.weekday() in (5, 6):
        return True
    return dt.hour >= 22 or dt.hour < 6


def analyze_activity(
    csv_file: Path,
    after_hours_only: bool = False,
    mass_threshold: int = 50,
) -> dict:
    if not csv_file.exists():
        raise FileNotFoundError(f"Файл журналів не знайдено: {csv_file}")

    logger.info(f"Reading user activity log {csv_file}...")

    records = []
    off_hours_alerts = []
    user_requests_per_min = defaultdict(lambda: defaultdict(list))
    total_records = 0

    with csv_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_records += 1
            ts_str = row["Timestamp"]
            user_id = row["UserID"]
            action = row["Action"]
            resource = row["Resource"]
            ip = row["IP"]

            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            record = {
                "timestamp": ts_str,
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "ip": ip,
            }
            records.append(record)

            if is_off_hours(dt):
                day_name = dt.strftime("%A")
                off_hours_alerts.append(
                    {
                        "user_id": user_id,
                        "timestamp": ts_str,
                        "time_only": dt.strftime("%H:%M:%S"),
                        "day_name": day_name,
                        "resource": resource,
                        "ip": ip,
                        "action": action,
                    }
                )

            minute_key = dt.strftime("%Y-%m-%d %H:%M")
            user_requests_per_min[user_id][minute_key].append(record)

    logger.info(f"Total records processed: {total_records}.")

    mass_download_alerts = []
    for user_id, min_dict in user_requests_per_min.items():
        for minute_key, reqs in min_dict.items():
            if len(reqs) >= mass_threshold:
                sample_action = reqs[0]["action"]
                sample_resource = reqs[0]["resource"]
                mass_download_alerts.append(
                    {
                        "user_id": user_id,
                        "count": len(reqs),
                        "action": sample_action,
                        "resource": sample_resource,
                        "minute_window": minute_key,
                    }
                )

    print("\n=== Off-Hours Activity Alerts (22:00–06:00 / Weekends) ===")
    for alert in off_hours_alerts:
        if "Saturday" in alert["day_name"] or "Sunday" in alert["day_name"]:
            msg = f"[ALERT] User '{alert['user_id']}' accessed '{alert['resource']}' on {alert['day_name']} {alert['timestamp']} from IP {alert['ip']}"
        else:
            msg = f"[ALERT] User '{alert['user_id']}' performed {alert['action']} action at {alert['time_only']} (Resource: {alert['resource']})"
        print(msg)

    print(f"\n=== Mass Download Anomalies (>{mass_threshold} requests/min) ===")
    for alert in mass_download_alerts:
        msg = f"[ALERT] User '{alert['user_id']}' executed {alert['count']} {alert['action']} requests to {alert['resource']} within 60 seconds."
        print(msg)

    return {
        "summary": {
            "total_records": total_records,
            "off_hours_count": len(off_hours_alerts),
            "mass_download_count": len(mass_download_alerts),
        },
        "off_hours_alerts": off_hours_alerts,
        "mass_download_alerts": mass_download_alerts,
    }


def main_cli() -> None:
    parser = argparse.ArgumentParser(
        description="Аналізатор журналів активності користувачів та виявлення аномалій (Варіант 7)"
    )
    parser.add_argument(
        "--activity-log",
        type=str,
        default="labs/lab02/data/data_v07/activity.csv",
        help="Шлях до вхідного CSV файлу активності",
    )
    parser.add_argument(
        "--after-hours",
        action="store_true",
        help="Прапорець аналізу додаткових позаробочих загрозах",
    )
    parser.add_argument(
        "--out-report",
        type=str,
        default="labs/lab02/data/off_hours_audit.json",
        help="Шлях для збереження підсумкового JSON-звіту",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Опціональний шлях до файлу логування дій",
    )
    parser.add_argument(
        "--mass-threshold",
        type=int,
        default=50,
        help="Поріг кількості запитів на хвилину",
    )

    args = parser.parse_args()
    setup_logging(args.log_file)

    try:
        csv_path = Path(args.activity_log)
        report_data = analyze_activity(
            csv_file=csv_path,
            after_hours_only=args.after_hours,
            mass_threshold=args.mass_threshold,
        )

        out_path = Path(args.out_report)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Anomalous activity report written to {out_path}")

    except (FileNotFoundError, KeyError, ValueError) as e:
        logger.error(f"Помилка виконання утиліти аудиту: {e}")


if __name__ == "__main__":
    main_cli()
