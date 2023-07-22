import os
import sys
import shutil
from pathlib import Path

import atternio.tools.commands as ccmd
import atternio.tools.fileoperations as fo


class Preparation:
    """Prepare the environment."""

    _path_dictionary = "attack-patterns"

    def __init__(self, auto_install: bool) -> None:
        self._auto_install = auto_install

    def _get_capec_data(self) -> None:
        """Get CAPEC data from official repository."""
        local_path_cti = Path(os.getenv("ROOTPATH"), "cti")
        ccmd.launch(f"git clone --depth 1 https://github.com/mitre/cti {local_path_cti}")
        fo.ucopy(
            Path(local_path_cti, "capec", "2.1", "attack-pattern"),
            Path(self._path_dictionary),
        )
        shutil.rmtree(local_path_cti)

    def check_capec_data(self) -> None:
        """Check the presence of CAPEC data in environment."""
        if not Path(self._path_dictionary).is_dir():
            print("\n[!] CAPEC dictionary is not present in the environment.")
            option = "y" if self._auto_install else input("[?] Would you like to install it? [yes/no] ")
            if option.lower() in ("yes", "y"):
                print("[*] Installing..")
                self._get_capec_data()
                print("[\u2713] Done!\n")
            elif option.lower() in ("no", "n"):
                print("\n[!] Exiting..\n")
                sys.exit(0)
            else:
                print("\n[\u2717] ERROR: Invalid option selected.\n")
                sys.exit(1)
