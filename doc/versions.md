## Version 1.2.14
1. support `MMT_U16_ARRAY` data type
2. Inspire5G+: add rule 79 to ensure DTLS traffic is in v1.2 or v1.3 and its ciphersuite is in a given list giving by `MMT_SEC_DTLS_CIPHER_ALLOWLIST` environment variable

## Version 1.2.12

1. support `MMT_U32_ARRAY` and `MMT_U64_ARRAY` data type
2. check unknown protocol and attribute names when compiling rules

## Version 1.2.11

1. fix bug when using embedded function `is_exist` to verify empty of attribute having numeric value. 
2. fix bug in boolean_expr when fun param is another function

## Version 1.2.10

1. support protocol names starting by a number, such as, `8021q`
2. add timeout event to trace when verifying type=SECURITY

## Version 1.2.9

1. support new data type of mmt-sdk: datetime and binary
2. fix bugs when ignoring the rest of flow

## Version 1.2.8

1. support `proto_hierarchy_t` data type
2. change output format of alert from `{key:val}` to `[key,val]`


## Version 1.2.7

1. remove warning when compiling using gcc 7.3

## Version 1.2.6

1. fix bug when add/rm rules at runtime, add user_data to message_t
2. to be able to stop verifying the rest of a flow when obtaining an alert on it
3. fix bugs that blocks mmt-security in multi-threading mode
4. allow setting `buffer_size` when enabling `ignore_remain_flow`

## Version 1.2.5

1. allow compiling to obtain static linkage
2. continue even not found any rules folders to load static linkage rules
3. fix a bug preventing visualization
4. improvement to ICMP rule


## Version 1.2.4

1. use `MMT_BASE` instead of `INSTALL_DIR`
2. resolve conflict of data type names with mmt-sdk


## Version 1.2.2

1. add `MMT_DPI_DIR` as parameter when doing `make` to indicate the folder containing mmt-sdk
2. limit 255 characters when reporting value of an attribute

## Version 1.2.1

1. add `INSTALL_DIR` as parameter when doing `make` to indicate target folder to be installed
2. disable by default the feature add/remove rules at runtime

## Version 1.2.0

1. Add or remove rules at runtime

## Version 1.1.5

1. implement `if_satisfied` function allowing user to perform some task when a rule is satisfied  
2. add document for developpers.

## Version 1.1.4

1. fix bug when printing alerts in JSON
2. inline some fn of fsm, filter out tcp flags=0, faster 30% verif bigFlows
3. compatible with gcc-7

## Version 1.1.3

1. add API to set/get thresholds
2. fix bug and more performance of converting data to JSON
3. support `on_load` and `on_unload` function implementation in embedded function tag
4. update Makefile: no need sudo to do "make deb"
5. high performance of mmt_hash_t
6. add default rule set to ./rules

## Version 1.1.2

1. Fix bug when we have more than one reference in boolean expression

2. Fix bug when getting ip.options 


## Version 1.1.1

1. Use minimal perfect hashing to access quickly to each elements of a `message_t` when giving protocol and attribute

2. Implement a masking system to filter out messages that does not concerns to some rules 

3. Create a wrapper in `mmt_security` to unify `mmt_single_security` and `mmt_smp_security`

4. Pre-implement some embedded functions

   - `is_exist` checks whether an attribute of a protocol, proto.att, exists in a `message_t`. This function also hides the proto.att from the masking
   - `is_empty` check whether a proto.att is `null` or its first byte is `'\0'`

5. Control versions of plugins, e.g., mmt-security loads only compatible plugins.

6. Auto testing