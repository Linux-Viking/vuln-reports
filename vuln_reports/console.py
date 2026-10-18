"""Terminal colour helpers shared by every command."""

from threading import Lock

print_lock = Lock()


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def colorize(text, color_code: str, use_colors: bool) -> str:
    if not use_colors:
        return str(text)
    return f"{color_code}{text}{Colors.END}"
