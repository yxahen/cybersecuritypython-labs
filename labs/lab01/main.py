import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from task1 import run_task1
from task2 import run_task2
from task3 import run_task3

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print(f"ЛАБОРАТОРНА РОБОТА №1 | {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    run_task1()
    print()
    run_task2()
    print()
    run_task3()


if __name__ == "__main__":
    main()
