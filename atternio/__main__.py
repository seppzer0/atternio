import os
import sys
import argparse
from pathlib import Path

from atternio.models import DataSearch
from atternio.models import Validation
from atternio.models import Preparation
from atternio.models import Enumeration


def parse_args():
    """Parse the arguments."""
    args = None if sys.argv[1:] else ["-h"]
    parser = argparse.ArgumentParser(
        description="Atternio - a PoC tool for CWE prioritization according to MITRE CAPEC dictionary.")
    parser.add_argument(
        "--source",
        required=True,
        dest="path_input",
        help="path to file or directory"
    )
    parser.add_argument(
        "--install-dictionary",
        dest="auto_install",
        action="store_true",
        help="if CAPEC dictionary is not present, install it automatically"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="path to output file"
    )
    parser.add_argument(
        "--results",
        action="store_true",
        help="show only RESULTS section"
    )
    return parser.parse_args(args)


def banner(banner_type: str, msg: str =""):
    """Print out banners."""
    if banner_type == "main":
        print("""

Welcome to..

 █████╗ ████████╗████████╗███████╗██████╗ ███╗   ██╗██╗ ██████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗████╗  ██║██║██╔═══██╗
███████║   ██║      ██║   █████╗  ██████╔╝██╔██╗ ██║██║██║   ██║
██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗██║╚██╗██║██║██║   ██║
██║  ██║   ██║      ██║   ███████╗██║  ██║██║ ╚████║██║╚██████╔╝
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝
""")
    elif banner_type == "mini":
        if not msg:
            print("[\u2717] ERROR: Message for banner was not provided")
            sys.exit(1)
        else:
            width = 18
            stars = "*" * width
            pad = (width + len(msg)) // 2
            print("\n")
            print("{0}\n{1:>{2}}\n{0}".format(stars, msg.upper(), pad))
    else:
        print("\n[\u2717] ERROR: Wrong banner type. \
               Possible values: 'main', 'mini'.\n")
        sys.exit(1)


def main(args: argparse.Namespace) -> None:
    os.environ["PYTHONUNBUFFERED"] = "1"
    banner("main")
    # control the output
    preparation = Preparation(args.auto_install)
    if not args.results and args.output:
        sys.stdout = open(args.output, "w")
    elif args.results:
        preparation.check_capec_data()
        redir = open(os.devnull, "w")
        sys.stdout = redir
    if not args.results:
        preparation.check_capec_data()
    # INPUT section
    banner("mini", "INPUT")
    Validation(args.path_input).check_input()
    # search CWE and CAPEC data
    banner("mini", "SEARCH CWE")
    datasearch = DataSearch(args.path_input)
    cwes = datasearch.cwe_search()
    banner("mini", "SEARCH CAPEC")
    capecs = datasearch.capec_search()
    # risk enumeration
    banner("mini", "RISK ENUMERATION")
    enumeration = Enumeration(capecs)
    enumeration.calculate_risks()
    if args.results:
        if args.output:
            sys.stdout = open(args.output, "w")
        else:
            sys.stdout = sys.__stdout__
    # print out results
    banner("mini", "RESULTS")
    enumeration.show_results(cwes)
    print("\n")
    # print message if output file was specified
    if args.output:
        sys.stdout = sys.__stdout__
        print("[\u2713] Output written to {} file!\n".format(args.output))


if __name__ == "__main__":
    # for print's to show in the right order
    #os.environ["PYTHONUNBUFFERED"] = "1"
    os.environ["ROOTPATH"] = str(Path(__file__).absolute().parents[1])
    main(parse_args())
