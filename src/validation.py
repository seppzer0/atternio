import sys
import os


def check_report(used_analyser, report_file):
    """An initial look at provided report."""
    supported_analysers = {
                            "cppcheck": [".xml",
                                         ".html"],
                            "bandit":   [".csv",
                                         ".html",
                                         ".json",
                                         ".txt",
                                         ".xml",
                                         ".yaml"]
    }
    filetype = os.path.splitext(report_file)[1]
    print("[*] Running checks on given report..")
    print("[*] Selected analyser: " + used_analyser)
    print("[*] Provided filetype: " + filetype)
    if used_analyser not in list(dict.fromkeys(supported_analysers)):
        print("\n[\u2717] ERROR: {} analyser type is not supported.\n"
              .format(used_analyser))
        sys.exit(1)
    else:
        if filetype not in supported_analysers[used_analyser]:
            print("\n[\u2717] ERROR: {} filetype for {} analyser is not "
                  "supported.\n".format(filetype, used_analyser))
            sys.exit(1)
        else:
            print("[\u2713] Checks complete!")
