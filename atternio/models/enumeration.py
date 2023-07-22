import sys
from tabulate import tabulate
from typing import List, Union


class Enumeration:
    """Risk calculations."""

    def __init__(self, capec_info: List[str]) -> None:
        self._capec_info = capec_info
        self._capec_points = {}
        self._cwe_capec = {}
        self._cwe_capec_sorted = []
        self._cwe_points = {}
        self._detected_cwes = []
        self._detected_capecs = []
        self._cwe_sorted = []
        self._cwe_capec_sorted = []
        self._total_risk = 0

    @staticmethod
    def _convert_metric(metric: str) -> Union[int, None]:
        """Convert metrics into numerical values."""
        numerical = {
            "Very High": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Very Low": 1,
        }
        if not metric:
            return 0
        elif metric not in numerical.keys():
            print("\n[\u2717] ERROR: Invalid metric value detected.\n")
            sys.exit(1)
        else:
            return numerical[metric]

    def calculate_risks(self) -> None:
        """Calculate based on retrieved CAPEC data."""
        print("[*] Calculating risks with retrieved CAPEC data..")
        for capec in self._capec_info:
            # extract values
            capec_risk = 0
            cwe = self._capec_info[capec]["cwe"]
            severity = self._convert_metric(self._capec_info[capec]["severity"].strip())
            likelihood = self._convert_metric(self._capec_info[capec]["likelihood"].strip())
            self._detected_cwes.append(cwe)
            self._detected_capecs.append(capec)
            # start risk calculation
            capec_risk += severity + likelihood
            if capec not in self._capec_points:
                self._capec_points[capec] = capec_risk
            else:
                self._capec_points[capec] += capec_risk
            # link cwes to their capecs
            if cwe not in self._cwe_capec:
                self._cwe_capec[cwe] = [capec]
                self._cwe_points[cwe] = capec_risk
            else:
                self._cwe_capec[cwe].append(capec)
                self._cwe_points[cwe] += capec_risk
            self._total_risk += capec_risk
        # sort by risk points
        self._cwe_sorted = {k: v for k, v in sorted(self._cwe_points.items(), key=lambda item: item[1], reverse=True)}
        # sync two lists
        for i in self._cwe_sorted.keys():
            for j, val in self._cwe_capec.items():
                if j == i:
                    self._cwe_capec_sorted.append("\n".join(val))
        print("[\u2713] Done!")

    def show_results(self, all_cwes: List[str]) -> None:
        """Print out the results."""
        table_all = {
            "No": list(range(1, (len(all_cwes.keys()))+1)),
            "CWE-ID": ["{}{}".format("CWE-", c) for c in all_cwes.keys()],
            "Location": ["\n".join(val) for key, val in all_cwes.items()]
        }
        table_prioritized = {
            "No": list(range(1, (len(self._cwe_sorted.keys()))+1)),
            "CWE-ID": [key for key, val in self._cwe_sorted.items()],
            "CAPEC-IDs": self._cwe_capec_sorted,
            "Share": ["{}{}".format(round(elem / self._total_risk * 100), "%")
                      for elem in list(self._cwe_sorted.values())]
        }
        print("- CWE RECORDS -")
        print(tabulate(table_all, headers="keys", tablefmt="grid"))
        print("\n- PRIORITIZED CWE RECORDS -")
        print(tabulate(table_prioritized, headers="keys", tablefmt="grid"))
