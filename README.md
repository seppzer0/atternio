# Introduction

Atternio is a simple tool for CWE prioritization according to MITRE CAPEC dictionary.

The tool utilises open source CAPEC data provided in the form of JSON (STIX 2.x) files.


## Algorithm

The prioritization process is done according to the following algorithm: 

1) The tool receives a SAST report as an input, from which all CWE numbers are extracted;

2) Each CWE is searched through CAPEC data to determine attack patterns (CAPEC-IDs) it can used in;

3) When analyzing CAPEC data, the following metrics are taken into account:
   * severity (`x_capec_severity`);
   * likelihood (`x_capec_likelihood_of_attack`).

4) An individual CWE can be found in multiple CAPEC-IDs.

   For each CWE in CAPEC-ID risk points are calculated using the following formula:
   ```txt
   cwe_risk = severity + likelihood
   ```

   Each CAPEC-ID can contain multiple detected CWEs:
   ```txt
   capec_risk = sum(cwe_risk)
   ```

   ```txt
   ```total_risk = sum(capec_risk)
   ```

5) When the risk enumeration is complete, the tool will output 4 tables:
   * `All Records` - all CAPEC-IDs and CWEs detected from provided report;
   * `Critical Records` - CAPEC-IDs and CWEs with most amount of risk points;
   * `Critical CAPEC-CWE` - pairs of critical CAPEC-IDs and CWEs;
   * `Risk Distribution` - % of each CAPEC-ID's risk points from total amount.

## Usage

```help
$ python3 src/app.py --help
usage: app.py [-h] [-o OUTPUT] [--results] analyser path_to_report

A tool for CWE prioritization according to MITRE CAPEC dictionary.

positional arguments:
  analyser              name of SAST tool used for the provided report
  path_to_report        path to report file

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        path to output file
  --results             show only RESULTS section
 ```


## Building

Standalone binary build:

```sh
pyinstaller -F --noupx src/app.py -n atternio
```

Docker image build:
```sh
docker build --no-cache . -t atternio
```

## Examples

Run directly from sources:
```sh
python3 src/app.py cppcheck report_samples cppcheck.xml
```

Run as a standalone binary:

```sh
./atternio cppcheck report_samples/cppcheck.xml
```

Run within a Docker container:
```sh
docker run --rm -it -v $(pwd)/report_samples:/report atternio cppcheck ../report/cppcheck.xml
```

## Supported SAST tools

The following SAST tools' reports are supported by atternio:

* Cppcheck (C/C++);
* Bandit (Python).
