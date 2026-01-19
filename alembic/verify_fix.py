from pathlib import Path
import sys

try:
    # Simulate the line that was failing
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src' / 'auth'))
    print("SUCCESS: Path inserted successfully")
    print(f"Path: {sys.path[0]}")
except TypeError as e:
    print(f"FAILURE: TypeError: {e}")
except Exception as e:
    print(f"FAILURE: Exception: {e}")
