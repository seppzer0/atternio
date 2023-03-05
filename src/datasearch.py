import os
import sys
import json
import glob


def search_cwe(used_analyser, report_file):
    """Search CWEs in provided report."""
    print("[*] Searching for CWEs..")
    cwes = []
    filetype = os.path.splitext(report_file)[1]
    # start analyzing provided report
    with open(report_file) as report_data:
        for line in report_data.readlines():
            # exclusively for cppcheck with .xml extension
            if used_analyser == "cppcheck" and filetype == ".xml":
                if "cwe" in line:
                    cwe_num = line.split('cwe="')[1].split('"')[0]
                    cwes.append(cwe_num)
            # every bandit format + cppcheck .html format
            else:
                sep = "https://cwe.mitre.org/data/definitions/"
                if sep in line:
                    cwe_num = line.split(sep)[1].split(".")[0]
                    cwes.append(cwe_num)
    # check if any cwes were extracted
    if not cwes:
        print("\n[!] No CWEs were found in the report, exiting..\n")
        sys.exit(0)
    # remove duplicates and convert to string for pretty view
    cwes = list(dict.fromkeys(cwes))
    print("[\u2713] Detected CWEs: ")
    for elem, num in enumerate(cwes):
        if (elem + 1) % 6 == 0:
            print(num)
        else:
            if elem % 6 == 0:
                print("    ", end="")
            print(num, end=" ")
    print("")
    return(cwes)


def capec_search(extracted_cwes, dict_path):
    """Search CAPEC data in JSONs."""
    # create a dictionary with necessary info
    # the format is:
    #       - CAPEC-ID;
    #       - CWE number;
    #       - x_capec_typical_severity;
    #       - x_capec_likelihood_of_attack
    capec_data = {}
    # search all JSONs for provided CWEs
    json_amnt = len(glob.glob1(os.path.normpath(dict_path), "*.json"))
    json_list = os.listdir(os.path.normpath(dict_path))
    print("[*] Searching CAPEC info for detected CWEs...")
    print("[*] Number of attack patterns in dictionary: " + str(json_amnt))
    for i in extracted_cwes:
        print("[*] Searching data for CWE-{}...".format(i))
        for j in json_list:
            with open(os.path.join(os.path.normpath(dict_path), j)) as file:
                fdata = json.load(file)
                for e in fdata["objects"][0]["external_references"]:
                    if "capec" in e["source_name"]:
                        capec_id = e["external_id"]
                    if "cwe" in e["source_name"]:
                        if "CWE-" + i in e["external_id"]:
                            print("[\u2713] Found CWE-{} in {}".format(i, j))
                            skey = "x_capec_typical_severity"
                            lkey = "x_capec_likelihood_of_attack"
                            severity = fdata["objects"][0][skey]
                            # "likelihood" might not be present in CAPEC data
                            likelihood = ""
                            if lkey not in fdata["objects"][0]:
                                pass
                            else:
                                likelihood = fdata["objects"][0][lkey]
                            capec_data[capec_id] = {
                                                    "cwe": "CWE-" + i,
                                                    "severity": severity,
                                                    "likelihood": likelihood
                                                    }
    # check any CAPEC data was extracted
    if not capec_data:
        print("\n[!] No CWEs found in CAPEC dictionary.\n")
        sys.exit(0)
    else:
        return(capec_data)
