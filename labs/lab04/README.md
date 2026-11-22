# ЛР №4. NVD API та автоматизоване тестування (варіант 7)

Консольна утиліта шукає запис CVE в NVD (CVE API 2.0) або читає локальну
відповідь із файла, перевіряє структуру даних і застосовує правило варіанта.

## Варіант 7

Напрям відбору: **високий вплив на доступність**.

Правило: `baseScore >= 7.0` **і** `cvssData.availabilityImpact == "HIGH"` — в одній
і тій самій вибраній оцінці CVSS v3.1. Це навчальне правило для ручного огляду,
а не пріоритет усунення вразливості.

Номер варіанта береться з `shared/student.py` (`VARIANT_NUMBER`).

## Встановлення

З кореня репозиторію, у віртуальному середовищі з Python 3.12+:

```bash
pip install requests pytest ruff
```

Версії зафіксовано в спільному `requirements.txt`.

## Запуск

Локальний режим (без мережі):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Один ручний запит до NVD:

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Необов'язковий ключ API передається змінною середовища `NVD_API_KEY`
(у заголовку `apiKey`, ніколи в URL і не в журналах).

Коди завершення: `0` — звіт сформовано (зокрема `not_found`,
`insufficient_data`); `1` — помилка отримання, читання чи перевірки даних;
`2` — неправильні аргументи або номер варіанта.

## Формат звіту

JSON-об'єкт у stdout з ключами: `cve_id`, `variant`, `description`,
`vuln_status`, `cvss_version`, `score`, `score_source`, `vector`, `rule`
(`threshold`, `field`, `expected`), `observed`, `decision`.
Відсутні значення — `null`.

`decision`: `not_found` → `rejected` → `insufficient_data` → `review` → `other`
(перша виконана умова за цим порядком).

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не виконують справжніх мережевих запитів (`tests/conftest.py`).
