import os
import sys
import json
import glob
from pathlib import Path
from typing import Union, Set

import atternio.tools.messages as msg
import atternio.tools.commands as ccmd


class DataSearch:
    """Search CWEs data in provided report."""

    _path_dictionary = "attack-patterns"

    def __init__(self, path_analyzed: str) -> None:
        self._path_analyzed = path_analyzed

    def cwe_search(self) -> Set[str]:
        """Search CWE identificators."""
        msg.note("Searching for CWEs..")
        report = "ffreport.html"
        cwes = {}
        ccmd.launch(
            f'python3 -m flawfinder -Q -D -H {self._path_analyzed} > {report}',
            quiet=True,
        )
        with open(report) as f:
            data = f.read()
        os.remove(report)
        blocks = data.split('<li>')[1:]
        for block in blocks:
            for line in block.splitlines():
                if self._path_analyzed in line:
                    cwe_loc = line.split(': <b>')[0]
                if "CWE-" in line:
                    cwe = line.split('CWE-')[1].split('</a>')[0]
                    if cwe not in cwes.keys():
                        cwes[cwe] = [cwe_loc]
                    else:
                        cwes[cwe].append(cwe_loc)
        print("[\u2713] Detected CWEs: ")
        for elem, num in enumerate(cwes.keys()):
            if (elem + 1) % 6 == 0:
                print("CWE-{}".format(num))
            else:
                if elem % 6 == 0:
                    print("    ", end="")
                print("CWE-{}".format(num), end=" ")
        print("")
        if not cwes:
            print("[!] No CWEs detected in provided sources, exiting..\n")
            sys.exit(1)
        return(cwes)

    def capec_search(self) -> Union[None, Set[str]]:
        """Search CAPEC data in JSONs."""
        capec_data = {}
        cwe_data = self.cwe_search().keys()
        json_amnt = len(glob.glob1(Path(self._path_dictionary), "*.json"))
        json_list = os.listdir(Path(self._path_dictionary))
        print("[*] Searching CAPEC info for detected CWEs...")
        print("[*] Number of attack patterns in dictionary: {}\n".format(str(json_amnt)))
        for i in cwe_data:
            print("[*] Searching data for CWE-{}...".format(i))
            related_capecs = []
            for j in json_list:
                with open(Path(self._path_dictionary, j)) as f:
                    fdata = json.load(f)
                    for e in fdata["objects"][0]["external_references"]:
                        if "capec" in e["source_name"]:
                            capec_id = e["external_id"]
                        if "cwe" in e["source_name"]:
                            if "CWE-" + i in e["external_id"]:
                                skey = "x_capec_typical_severity"
                                lkey = "x_capec_likelihood_of_attack"
                                severity = ""
                                likelihood = ""
                                if skey not in fdata["objects"][0]:
                                    pass
                                else:
                                    severity = fdata["objects"][0][skey]
                                if lkey not in fdata["objects"][0]:
                                    pass
                                else:
                                    likelihood = fdata["objects"][0][lkey]
                                related_capecs.append(capec_id)
                                capec_data[capec_id] = {
                                    "cwe": "CWE-" + i,
                                    "severity": severity,
                                    "likelihood": likelihood
                                }
            if related_capecs:
                print("[\u2713] Found CWE-{} in CAPECs:".format(i))
                for elem, num in enumerate(related_capecs):
                    if (elem + 1) % 6 == 0:
                        print(num)
                    else:
                        if elem % 6 == 0:
                            print("    ", end="")
                            print(num, end=" ")
                print("\n")
        if not capec_data:
            print("\n[!] No detected CWEs found in CAPEC dictionary, exiting..\n")
            sys.exit(1)
        else:
            return(capec_data)
