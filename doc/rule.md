# Sample rules

There are two sample rules in [../rules/](../rules/)

# Embedded functions

## Implement a new embedded function
In each rule file, there exists a section allowing user to add an embedded function.

```xml
<embedded_functions><![CDATA[

code C

]]></embedded_functions>
``` 


## Pre-installed embedded functions

In boolean expressions of rules, one can use one or many embedded functions

- `is_exist( proto.att )`

- `is_empty( proto.att )`, e.g., `is_empty(http.uri)`