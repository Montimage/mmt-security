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