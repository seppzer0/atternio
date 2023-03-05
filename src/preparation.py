import os
import sys
import shutil
import subprocess


def get_capec_data(dict_path):
    """Get CAPEC data from official repository."""
    subprocess.run("git clone --depth 1 https://github.com/mitre/cti",
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                   shell=True, check=True)
    shutil.copytree(os.path.join("cti", "capec", "2.1", "attack-pattern"),
                    os.path.normpath(dict_path))
    shutil.rmtree("cti")


def check_capec_data(dict_path):
    """Check the presence of CAPEC data in environment."""
    if not os.path.isdir(os.path.normpath(dict_path)):
        print("\n[!] CAPEC dictionary is not present in the environment.")
        option = input("[?] Would you like to install it? [yes/no] ")
        if option.lower() in ["yes", "y"]:
            print("[*] Installing..")
            get_capec_data(dict_path)
            print("[\u2713] Done!\n")
        elif option.lower() in ["no", "n"]:
            print("\n[!] Exiting..\n")
            sys.exit(0)
        else:
            print("\n[\u2717] ERROR: Invalid option selected.\n")
            sys.exit(1)
