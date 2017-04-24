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