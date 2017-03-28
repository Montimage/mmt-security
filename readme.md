# MMT-Security

This repository contains mmt-security toolset:

- `compile_rule`: encode .xml rules into a shared library (file .so)
- `rule_info`: get information of one or all encoded rules
- `mmt_sec_standalone`: use mmt-security to analyse realtime traffic or pcap file
- `mmt_sec_server`: analyse meta-data sent by mmt-probe

# Build

## Pre-requires

Suppose on your machine, you have:

- *libxml2-dev, libpcap-dev, libconfuse-dev* : 

```bash
sudo apt-get install libxml2-dev libpcap-dev libconfuse-dev
```

- *hiredis*

```bash
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
ldconfig
```

- *mmt-sdk*: see https://bitbucket.org/montimage/mmt-sdk/wiki/Compilation%20and%20Installation%20Instructions

- *source code of mmt-security* 

```bash
git clone https://bitbucket.org/montimage/mmt-security
```

## Compile


- *compile mmt-security on its local directory
```
make
```

- *compile mmt-security to get .deb file in order to re-distribute its binary*

```
make deb
```

you will get a .deb file, e.g., `mmt-security_1.0.1_8d5d7ea_Linux_x86_64.deb`, containing everything mmt-security need in order to be able to execute on a new machine.


# Execution

MMT-Security binary can be obtained by compiling its source code or installing its distribution file (*.deb).

## compile_rule
This application parses rules in .xml file, then compile to a plugin .so file.

```bash
#generate .so file
./compile_rule rules/arp_poisoning.so rules/arp_poisoning.xml
#generate code c
./compile_rule rules/arp_poisoning.c rules/arp_poisoning.xml -c
```

## rule_info

This application prints information of rules encoded in a binary file (.so).

```bash
#print information of all available plugins
./rule_info
#print information of rules encoded in `./rules/arp_poisoning.so`
./rule_info ./rules/arp_poisoning.so
```

## mmt-sec-standalone

This application can analyze
 
- either real-time traffic by monitoring a NIC,
- or traffic saved in a pcap file. The verdicts will be printed to the current screen.

```bash
#online analysis on eth0
./mmt_sec_standalone -i eth0
#to see all parameters, run ./mmt_sec_standalone -h
#verify a pcap file
./mmt_sec_standalone -t ./tata.pcap
```
