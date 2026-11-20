# MMT-Security

This repository contains the following folders:

- `src` : C code of mmt-security
- `rules`: set of official XML rules. An encoded version (*.so) of these rules will be distributed with mmt-sec when using `make deb`. All rules (official and for testing purposes) are stored in rules/properties_all 
- `check`: sample pcap files and expected results to validate mmt-security
- `doc`: [documentation](doc/)
- `test`: diversity of testing code

The repository contains mmt-security toolset:

- `compile_rule`: encode .xml rules into a shared library (file .so)
- `rule_info`: get information of one or all encoded rules
- `mmt_sec_standalone`: use mmt-security to analyse realtime traffic or pcap file
- `mmt_sec_server`: analyse meta-data sent by mmt-probe

# Build

## Pre-requires

Suppose on your machine, you have:

- *libxml2-dev, libpcap-dev, libconfuse-dev* :  `sudo apt-get install libxml2-dev libpcap-dev libconfuse-dev`

- Optional: *hiredis*
```bash
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
ldconfig
```

- [`mmt-dpi`](//github.com/montimage/mmt-dpi)

- source code of mmt-security

```bash
git clone https://github.com/Montimage/mmt-security.git
```

## Clean

```bash
cd mmt-security
```
- Do `make clean` to clean compiled objects of mmt-security
- Do `make clean-all` to clean all compiled objects of mmt-security and the ones being generated from mmt-sdk. Thus do this when mmt-sdk has been updated.


## Compile


- compile MMT-Security on its local directory: `make`

- compile sample rules existing in `rules` folder: `make sample_rules`

- enable some modules use: `make [MODULE_NAME=1]+`. Currently `MODULE_NAME` is one of the followings:

    - `REDIS`: this module allows to output to redis. Consequently `hiredis` library must be installed. 
    - `UPDATE_RULES`: this module allows to add or remove rules at runtime. This is enabled by default. To disable this, e.g., in the case we do not need this feature: `MODULE_NAME=0`

- compile mmt-security to get .deb file in order to re-distribute its binary: `make deb`  
   You will get a .deb file, e.g., `mmt-security_1.0.1_8d5d7ea_Linux_x86_64.deb`, containing everything mmt-security needs in order to be able to execute on a fresh machine.  
   To install this deb file on a new debian-based machine, use: `sudo dpkg -i file_name.deb`

- install mmt-security on the current machine: `make install`

- debug MMT-Security: `make DEBUG=1`


- if you want to check MMT-Security using Valgrind DRD or Helgrind, you should do `make DEBUG=1 VALGRIND=1`. The option `VALGRIND=1` adds some instruction allowing Valgrind bypass atomic operations that usually causes false positive errors in Valgrind.

## Install directory

By default, MMT-Security will be installed on `/opt/mmt/security`. 
We can change the directory by giving giving a new directory name to `INSTALL_DIR` parameter when doing `make` and `make install`. For example:

```
make INSTALL_DIR=/home/tata/security
make install INSTALL_DIR=/home/tata/security
```

# Execution

MMT-Security binary files can be obtained by compiling its source code or installing its distribution file (*.deb).

## compile_rule
This application parses rules in .xml file, then compile to a plugin .so file.

```bash
#to generate .so file
./compile_rule rules/40.TCP_SYN_scan.so rules/40.TCP_SYN_scan.xml 
#to generate code c (for debug)
./compile_rule rules/40.TCP_SYN_scan.c rules/40.TCP_SYN_scan.xml -c
```

To compile all rules existing in the folder `rules`, use the following command:

```bash
make sample_rules
```

## rule_info

This application prints information of rules encoded in a binary file (.so).

```bash
#print information of all available plugins
./rule_info
#print information of rules encoded in `rules/40.TCP_SYN_scan.so`
./rule_info rules/40.TCP_SYN_scan.so
```

## mmt_sec_standalone

This application can analyze
 
- either real-time traffic by monitoring a NIC,
- or traffic saved in a pcap file. The verdicts will be printed to the current screen.

```bash
./mmt_sec_standalone [<options>]
Option:
   -t <trace file>: Gives the trace file to analyse.
   -i <interface> : Gives the interface name for live traffic analysis.
   -c <string>    : Gives the range of logical cores to run on, e.g., "1,3-8,16"
   -x <string>    : Gives the range of rules id to be excluded, e.g., "99,107-1010".
   -m <string>    : Attributes special rules to special threads using format (lcore:range) e.g., "(1:1-8,10-13)(2:50)(4:1007-1010)".
   -f <string>    : Output results to file, e.g., "/home/tata/:5" => output to folder /home/tata and each file contains reports during 5 seconds 
   -r <string>    : Output results to redis, e.g., "localhost:6379"
   -g             : Ignore the rest of a flow when an alert was detetected on the flow.
   -v             : Verbose.
   -l             : Prints the available rules then exit.
   -h             : Prints this help.
   
#online analysis on eth0
./mmt_sec_standalone -i eth0
#to see all parameters, run ./mmt_sec_standalone -h
#verify a pcap file
./mmt_sec_standalone -t check/pcap/16.two_successive_SYN.pcap 

```

## mmt_sec_server

This application receives meta-data, calling `messages`, from mmt-probe via internet or Unix sockets and then analyse them.

```bash
./mmt_sec_server -h
MMT-Security version 1.1.2 (14bade8 - Apr 24 2017 18:00:35)
./mmt_sec_server [<option>]
Option:
   -p <number/string> : If p is a number, it indicates port number of internet domain socket otherwise it indicates name of unix domain socket. Default: 5000
   -n <number> : Number of threads per process. Default = 1
   -c <string> : Gives the range of logical cores to run on, e.g., "1,3-8,16"
   -x <string> : Gives the range of rules id to be excluded from verification, e.g., "1,3-8,16"
   -m <string> : Attributes special rules to special threads e.g., "(1:10-13)(2:50)(4:1007-1010)"
   -f <string> : Output results to file, e.g., "/home/tata/:5" => output to folder /home/tata and each file contains reports during 5 seconds 
   -r <string> : Output results to redis, e.g., "localhost:6379"
   -v          : Verbose.
   -l          : Prints the available rules then exit.
   -h          : Prints this help.
```

# Auto testing

After modified code, you should run `make check` to validate the modifications.
Use `make check VAL=1` to check memory leak using valgrind (thus valgrind need to be installed before).

These commands will do the followings:

- run `mmt_sec_standalone` to check all properties in `rules`
against the pcap files in `check/pcap/`

- compare the alerts generated by each run with the expected ones in `check/expect/`

The log of each run can be found in `/tmp/` 

`make check` first runs `make check-attack`, which checks the MITRE ATT&CK mapping below. It needs only `python3` and no network.

# MITRE ATT&CK mapping

`rules/mitre-attack.csv` maps each rule of `rules/*.xml` to the [MITRE ATT&CK Enterprise](https://attack.mitre.org/) technique that its alert is evidence of, so that SIEMs, STIX consumers and dashboards share one mapping. It has one row per rule file:

| Column | Content |
|---|---|
| `rule_id` | the rule's `property_id` |
| `rule_file` | the file name in `rules/`, e.g. `40.TCP_SYN_scan.xml` |
| `technique_id` | an ATT&CK technique or sub-technique ID, e.g. `T1046` or `T1557.002`, or `none` when no technique fits, e.g. a malformed or odd packet on its own |
| `technique_name` | the technique's name in the pinned ATT&CK version, as on attack.mitre.org (`Parent: Sub-technique`); empty for `none` |
| `tactic` | one of the technique's tactics, the one the rule's context points to; empty for `none` |
| `confidence` | `high`: the condition is specific to the technique. `medium`: the technique is the right reading, but the condition also matches other activity or another technique could apply. `low`: a judgement call, or a rule known to fire on normal traffic; to review. On a `none` row: how sure it is that no technique applies |
| `cve_ids` | space-separated CVE IDs, only when the rule detects the exploitation of a specific vulnerability; empty for behaviour-based rules (scans, floods, brute force, malformed packets) |
| `cve_source` | the record URL of each CVE ID, on `https://www.cve.org/` or `https://nvd.nist.gov/`, space-separated; empty without CVE IDs |
| `rationale` | one sentence on what the rule's boolean expression actually checks, and why it supports the technique (or `none`) |

The ATT&CK version is pinned: `check/attack/enterprise-attack-techniques.csv` lists every technique of that version (not revoked, not deprecated) with its name and tactics. Its header gives the version, the source URL of the bundle and its sha256. It is generated by `check/attack/gen-attack-techniques.py` from the `enterprise-attack` bundle of MITRE's [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository.

`make check-attack` fails if a rule has no row or more than one, if a row points to a missing rule or has a wrong `rule_id`, if a technique ID is not in the pinned version, or its name or tactic does not match, if a confidence or a rationale is missing, if a row has missing or extra fields, or if a CVE ID is not of the form `CVE-YYYY-NNNN`, is on a `none` row or is not cited by a cve.org or NVD URL in `cve_source`.

The mapping is not installed with the rules (`make install` and `make deb` copy only `rules/*.so`); integrators take it from this repository.

## When a rule is added

1. Add one row for the new file to `rules/mitre-attack.csv`. Read the rule's boolean expressions, not only its name: pick the technique the condition is evidence of, or `none`, and quote the condition in the rationale.
2. Copy `technique_name` and pick `tactic` from `check/attack/enterprise-attack-techniques.csv`.
3. Add a CVE only when the rule targets that vulnerability, after checking its record on [cve.org](https://www.cve.org/) or NVD; put the record URL in `cve_source`.
4. Run `make check-attack`.

## Moving to a newer ATT&CK version

1. Find the latest release of [attack-stix-data](https://github.com/mitre-attack/attack-stix-data/releases), e.g. `v20.1`.
2. Regenerate the list: `python3 check/attack/gen-attack-techniques.py --version 20.1` (it downloads the bundle; `--bundle <file>` uses a local copy instead).
3. Run `make check-attack`. Techniques that were revoked, deprecated, renamed or moved to another tactic are reported; fix those rows, reading the release notes of the new version.

# Documentation

[doc](doc/)
