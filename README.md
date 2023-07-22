# Introduction

Atternio is a PoC tool powered by [flawfinder](https://github.com/david-a-wheeler/flawfinder) for CWE prioritization according to MITRE CAPEC dictionary.

The tool utilises open source CAPEC data provided in the form of JSON (STIX 2.x) files.

## Algorithm

The tool receives a path to C/C++ sources as an input, which is passed to flawfinder to find CWEs.

Each CWE is searched through CAPEC data to determine attack patterns (CAPEC-IDs) it can used in.

When analyzing CAPEC data, the following metrics are taken into account:

* Severity (`x_capec_severity`);
* Likelihood (`x_capec_likelihood_of_attack`).

An individual CWE can be found in multiple CAPEC-IDs.

For each CWE in CAPEC-ID risk points are calculated using the following formula:

```text
cwe_risk = severity + likelihood
```

Each CAPEC-ID can contain multiple detected CWEs:

```text
capec_risk = sum(cwe_risk)
```

Finally, the total number of risk points:

```text
total_risk = sum(capec_risk)
```

When the risk enumeration is complete, the tool will output 2 tables:

* **CWE Records** - all CWEs detected with their location in provided sources;
* **Prioritized CWE Records** - prioritized CWEs with related CAPECs and percentage of shared risk.

## Usage

```help
$ python3 atternio/ --help
usage: [-h] --source PATH_INPUT [--install-dictionary] [-o OUTPUT] [--results]

Atternio - a PoC tool for CWE prioritization according to MITRE CAPEC dictionary.

optional arguments:
  -h, --help            show this help message and exit
  --source PATH_INPUT   path to file or directory
  --install-dictionary  if CAPEC dictionary is not present, install it
                        automatically
  -o OUTPUT, --output OUTPUT
                        path to output file
  --results             show only RESULTS section
 ```
