from collections import Counter
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
FILE = PROJECT_DIR / "data" / "urls.txt"
lines = FILE.read_text(encoding="utf-8").splitlines()

duplicates = {
    line: count
    for line, count in Counter(lines).items()
    if count > 1
}

if duplicates:
    print(f"Found {len(duplicates)} duplicates")
    print(duplicates)
    
    unique_lines = list(dict.fromkeys(lines))
    FILE.write_text(
        "\n".join(unique_lines),
        encoding="utf-8"
    )
    print(f"Removed {len(lines) - len(unique_lines)} duplicate lines.")
    print(f"Total URLs: {len(unique_lines)}")
else:
    print("No duplicates found")
    print(f"Total URLs: {len(lines)}")