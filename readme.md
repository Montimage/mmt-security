# MMT-Security

This repository contains mmt-security toolset:

- compile_rule: encode .xml rules into a shared library (file .so)
- rule_info: get information of one or all encoded rules
- standalone: use mmt-security to analyse realtime traffic or pcap file

## compile_rule

Parse rules in .xml file, then generate .c file, then compile to a plugin .so file.

### compile

```makefile
make compile_rule
```

### run

```bash
./compile_rule rules/rule_acdc.so test/xml/properties_acdc.xml
```

## rule_info

Get information of rules encoded in a binary file (.so).

### compile 

```makefile
make rule_info
```

### run

```bash
#print information of all available plugins (located in `./rules` and `/opt/mmt/security/rules`)
./rule_info
#print information of rules encoded in `./rules/rule_acdc.so`
./rule_info ./rules/rule_acdc.so
```

## mmt-sec-standalone

This application can analyze 
- either real-time traffic by monitoring a NIC,
- or traffic saved in a pcap file. The verdicts will be printed to the current screen.

### compile

```makefile
make standalone
```


### run


```bash
./mmt_security
```
