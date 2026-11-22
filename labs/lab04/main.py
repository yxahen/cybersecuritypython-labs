import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


class CliError(Exception):
    pass


def _cve_id(value: str) -> str:
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "очікується формат CVE-YYYY-NNNN (регістр має значення)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Перегляд запису CVE в NVD за правилом варіанта.",
    )
    parser.add_argument("--cve", required=True, type=_cve_id, help="ідентифікатор CVE")
    parser.add_argument(
        "--input", help="шлях до локальної відповіді NVD (без мережевих запитів)"
    )
    return parser


def load_response(path: Path) -> Any:
    """Читає UTF-8 JSON-файл із відповіддю NVD."""
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def _read_local(path: Path) -> Any:
    try:
        return load_response(path)
    except OSError as exc:
        raise CliError(
            f"Не вдалося прочитати файл: {path} ({type(exc).__name__})."
        ) from exc
    except ValueError as exc:
        raise CliError("Файл не є коректним UTF-8 JSON.") from exc


def _fetch_remote(cve_id: str) -> Any:
    try:
        return api_client.fetch_response(cve_id)
    except requests.exceptions.Timeout as exc:
        raise CliError("Перевищено час очікування відповіді NVD.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise CliError("Не вдалося встановити з'єднання з NVD.") from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "невідомий"
        raise CliError(f"NVD повернув HTTP-помилку, код статусу: {status}.") from exc
    except requests.exceptions.JSONDecodeError as exc:
        raise CliError("Відповідь NVD не є коректним JSON.") from exc
    except api_client.UnexpectedStatusError as exc:
        raise CliError(
            f"Неочікуваний статус відповіді NVD: {exc.status_code}."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise CliError("Помилка під час виконання запиту до NVD.") from exc


def main(argv: list[str] | None = None) -> int:
    """Точка входу: повертає код завершення (0, 1 або 2)."""
    variant = VARIANT_NUMBER
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not 1 <= variant <= 15
    ):
        print(
            "Помилка: номер варіанта має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    args = build_parser().parse_args(argv)
    try:
        if args.input:
            payload = _read_local(Path(args.input))
        else:
            payload = _fetch_remote(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except CliError as exc:
        print(f"Помилка: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Помилка перевірки даних: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
