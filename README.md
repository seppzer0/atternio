# atternio

atternio is a PoC tool powered by [flawfinder](https://github.com/david-a-wheeler/flawfinder) that is designed to prioritize CWE identificators according to [MITRE CAPEC](https://capec.mitre.org) dictionary.

The data used for conducting this procedure is open source CAPEC data provided in the form of JSON (STIX 2.x) files.

## Contents

- [atternio](#atternio)
  - [Contents](#contents)
  - [Algorithm](#algorithm)
  - [Usage](#usage)
  - [Installation](#installation)
    - [From PyPI (recommended)](#from-pypi-recommended)
    - [Local from source](#local-from-source)
    - [No installation, direct run from source](#no-installation-direct-run-from-source)

## Algorithm

atternio receives a path to C/C++ sources as an input, which is then passed to flawfinder for finding out CWEs.

Each CWE identificator is searched through CAPEC data to determine the attack patterns (CAPEC-IDs) it can be a part of.

When analyzing CAPEC data, the following metrics are taken into account:

- severity (`x_capec_severity`);
- likelihood (`x_capec_likelihood_of_attack`).

An individual CWE can be found in multiple CAPEC patterns.

For each CWE (CWE-ID) in a CAPEC pattern (CAPEC-ID) risk points are calculated using the following formula:

```text
cwe_risk = severity + likelihood
```

Each CAPEC-ID can contain multiple detected CWE-IDs:

```text
capec_risk = sum(cwe_risk)
```

Finally, the total number of risk points:

```text
total_risk = sum(capec_risk)
```

When the risk enumeration is complete, the tool will output 2 tables:

- **CWE Records** - all CWEs detected with their location in provided sources;
- **Prioritized CWE Records** - prioritized CWEs with related CAPECs and percentage of shared risk.

## Usage

```help
$ python3 -m atternio --help
usage: [-h] --source PATH_INPUT [--install-dictionary] [-o OUTPUT] [--results]

Atternio - a PoC tool for CWE prioritization according to MITRE CAPEC dictionary.

options:
  -h, --help            show this help message and exit
  --source PATH_INPUT   path to file or directory
  --install-dictionary  if CAPEC dictionary is not present, install it automatically
  -o OUTPUT, --output OUTPUT
                        path to output file
  --results             show only RESULTS section
 ```

## Installation

### From PyPI (recommended)

To install latest atternio package from PyPI, use:

```sh
python3 -m pip install atternio
```

### Local from source

To install and debug atternio locally, in the root of repository use:

```sh
python3 -m pip install -e .
```

### No installation, direct run from source

To run atternio without any installation into local cache, in the root of repository use:

```sh
export PYTHONPATH=$(pwd)
python3 -m poetry install --no-root
python3 atternio <arguments>
```
