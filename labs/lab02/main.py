import sys

from labs.lab02.task1 import run_demo
from labs.lab02.task2 import main_cli


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        if len(sys.argv) > 1 and sys.argv[1] == "analyze":
            sys.argv.pop(1)
        main_cli()


if __name__ == "__main__":
    main()
