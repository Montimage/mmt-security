# MMT-Security

This repository contains mmt-security toolset:

- gen_plugin: encode .xml rules into a shared library (file .so)
- plugin_info: get information of one or all encoded rules
- standalone: use mmt-security to analyse realtime traffic or pcap file

## gen_plugin

Parse rules in .xml file, then generate .c file, then compile to a plugin .so file.

### compile

```makefile
make gen_plugin
```

### run

```bash
./gen_plugin rules/rule_acdc.so test/xml/properties_acdc.xml
```

## plugin_info

Get information of rules encoded in a binary file (.so).

### compile 

```makefile
make plugin_info
```

### run

```bash
#print information of all available plugins (located in `./rules` and `/opt/mmt/security/rules`)
./plugin_info
#print information of rules encoded in `./rules/rule_acdc.so`
./plugin_info ./rules/rule_acdc.so
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
./mmt_sec_standalone
```
