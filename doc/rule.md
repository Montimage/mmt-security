# Sample rules

There are two sample rules in [../rules/](../rules/)

# Special terms

1. `true` will be replaced by the number 1. For example 

   `#check( tcp.src_port ) == true`

2. `false` will be replaced by the number 0. For example 

   `#check( tcp.src_port ) == false`

# Embedded functions

Embedded functions are functions that allow implementing calculations that are too complicated to define using only classical operators on fields in the Boolean expressions of security properties. One can use existing embedded functions or implement a new function. In both cases, they can be used in the Boolean expressions by using the syntax:

`#<name_of_function>(<list of parameters>)`

For instance:

   `(#em_is_search_engine( http.user_agent ) == true)`
   
where `http` is the protocol name and `user_agent` is the attribute name (i.e., packet meta-data).


## Implement a new embedded function
In each rule file, there exists a section allowing user to add an embedded function.

```xml
<embedded_functions><![CDATA[

code C

]]></embedded_functions>
``` 

One can implement the 2 following functions:

1. `void on_load(){ ... }` being called when the rules inside the xml file being loaded into MMT-Security

2. `void on_unload(){ ... }` being called when exiting MMT-Security

MMT-Security engine will call these functions only if they exist.

## Pre-installed embedded functions

In boolean expressions of rules, one can use one or many embedded functions

1. `is_exist( proto.att )`  checks whether an event has an attribute of a protocol, e.g., `is_exist( http.method )` will return `true` if the current event contains protocol `HTTP` and attribute method has a non-null value, otherwise it will return `false`.

2. `is_empty( proto.att )`, e.g., `is_empty(http.uri)` checks whether the string value is empty, i.e., its length is zero.

3. User can use any standard C functions as embedded function, e.g., `(#strstr( http.user_agent, 'robot') != 0)` to check if `http.user_agent` contains a sub-string `"robot"`.