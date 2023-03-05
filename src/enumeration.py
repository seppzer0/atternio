import sys
import time
import operator
from tabulate import tabulate


def convert_metric(metric):
    """Convert metrics into numerical values."""
    if metric == "Very High":
        metric = 5
    elif metric == "High":
        metric = 4
    elif metric == "Medium":
        metric = 3
    elif metric == "Low":
        metric = 2
    elif metric == "Very Low":
        metric == 1
    # this is specifically for empty "likelihood" values
    elif not metric:
        metric = 0
    else:
        print("\n[\u2717] ERROR: Invalid metric value detected.\n")
        sys.exit(1)
    return(metric)


def calculate_risks(capec_info):
    """Calculate based on retrieved CAPEC data."""
    print("[*] Calculating risks with retrieved CAPEC data..")
    global total_risk, \
        detected_cwes, \
        detected_capecs, \
        capec_cwe_pair, \
        capec_crit, \
        cwe_crit, \
        capec_unique
    capec_unique = {}
    capec_cwe_pair = {}
    detected_cwes = []
    detected_capecs = []
    total_risk = 0
    for elem in capec_info:
        # extract values
        capec_risk = 0
        capec = elem
        cwe = capec_info[elem]["cwe"]
        severity = convert_metric(capec_info[elem]["severity"])
        likelihood = convert_metric(capec_info[elem]["likelihood"])
        detected_cwes.append(cwe)
        detected_capecs.append(capec)
        # start risk calculation
        capec_risk += severity + likelihood
        if capec not in capec_unique:
            capec_unique[capec] = capec_risk
            capec_cwe_pair[capec] = [cwe]
        else:
            capec_unique[capec] += capec_risk
            capec_cwe_pair[capec] += [cwe]
        total_risk += capec_risk
    # find CAPECs (and CWEs within them) with max amount of risk points
    capec_crit = []
    cwe_crit = []
    for capec_id, risk_points in capec_unique.items():
        if risk_points == max(capec_unique.items(),
                              key=operator.itemgetter(1))[1]:
            capec_crit.append(capec_id)
            cwe_crit.append("\n".join(capec_cwe_pair[capec_id]))
    print("[\u2713] Done!")


def show_results():
    """Print out the results."""
    table_general = {
        "CAPEC-ID": list(dict.fromkeys(detected_capecs)),
        "CWE-ID": list(dict.fromkeys(detected_cwes))
    }
    table_critical = {
        "CAPEC-ID": capec_crit,
        "CWE-ID": list(dict.fromkeys(cwe_crit))
    }
    table_relations = {
        "CAPEC-ID": list(dict.fromkeys(detected_capecs)),
        "CWE-ID": ["".join(elem)
                   for elem in list(capec_cwe_pair.values())]
    }
    table_points = {
        "CAPEC-ID": detected_capecs,
        "Points": list(capec_unique.values()),
        "Share": ["{}{}".format(round(elem / total_risk * 100), "%")
                  for elem in list(capec_unique.values())]
    }
    print("- ALL RECORDS -")
    print(tabulate(table_general, headers="keys", tablefmt="grid"))
    print("\n- CRITICAL RECORDS -")
    print(tabulate(table_critical, headers="keys", tablefmt="grid"))
    print("\n- CRITICAL CAPEC-CWE -")
    print(tabulate(table_relations, headers="keys", tablefmt="grid"))
    print("\n- RISK DISTRIBUTION -")
    print(tabulate(table_points, headers="keys", tablefmt="grid"))
