import sys
import os
from pathlib import Path


class Validation:
    """Run validation on input data."""

    def __init__(self, input_path) -> None:
        self._input_path = input_path

    def check_input(self) -> None:
        """An initial look at provided input."""
        print("[*] Running checks on given input..")
        print(f"[*] Provided path: {self._input_path}")
        check = False
        valid_ff = [".c", ".cc", ".cpp"]
        if Path(self._input_path).is_dir():
            for path, subdirs, files in os.walk(self._input_path):
                for fn in files:
                    if os.path.splitext(fn)[-1].lower() in valid_ff:
                        check = True
        elif Path(self._input_path).is_file():
            if os.path.splitext(self._input_path)[-1].lower() in valid_ff:
                check = True
        else:
            print("\n[\u2717] ERROR: Provided input is not a file nor a directory.\n")
            sys.exit(1)
        if not check:
            print("\n[\u2717] ERROR: Provided input file format is not compatible "
                  "for checks.\n")
            sys.exit(1)
        else:
            print("[\u2713] Checks complete!")
