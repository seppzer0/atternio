import io
import os
import sys
import argparse
import preparation
import validation
import datasearch
import enumeration


def parse_args():
    """Parse the arguments."""
    parser = argparse.ArgumentParser(description="Atternio - a tool for CWE \
                                      prioritization according \
                                      to MITRE CAPEC dictionary.")
    parser.add_argument("analyser",
                        help="name of SAST tool used for the provided report")
    parser.add_argument("path_to_report",
                        help="path to report file")
    parser.add_argument("-o", "--output",
                        help="path to output file")
    parser.add_argument("--results",
                        action="store_true",
                        help="show only RESULTS section")
    global args
    args = parser.parse_args()


def banner(banner_type, msg=""):
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


# create local variables
parse_args()
analyser = args.analyser
report = args.path_to_report
output = args.output
results_only = args.results
dictionary_path = "attack-patterns"
# initial checks
banner("main")
# control the output
if not results_only and output:
    sys.stdout = open(output, "w")
elif results_only:
    preparation.check_capec_data(dictionary_path)
    redir = open(os.devnull, "w")
    sys.stdout = redir
if not results_only:
    preparation.check_capec_data(dictionary_path)
banner("mini", "INPUT")
validation.check_report(analyser, report)
# CWE analysis
banner("mini", "SEARCH CWE")
cwes = datasearch.search_cwe(analyser, report)
banner("mini", "SEARCH CAPEC")
capecs = datasearch.capec_search(cwes, dictionary_path)
# risk enumeration
banner("mini", "RISK ENUMERATION")
enumeration.calculate_risks(capecs)
if results_only:
    if output:
        sys.stdout = open(output, "w")
    else:
        sys.stdout = sys.__stdout__
# print out results
banner("mini", "RESULTS")
enumeration.show_results()
print("\n")
# print message if output file was specified
if output:
    sys.stdout = sys.__stdout__
    print("[\u2713] Output written to {} file!\n".format(output))
