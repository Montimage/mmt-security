Rules mask is a string. It is used to distribute rules on each thread.

## Syntax
It respects the following BNF syntax:

`
rules_mask :== (number:range)+
range      := number | number-range | number,range
number     := (1-9)+
`

### Example

`
"(1:1-4,6)(2:5,7-10)"
`

This rules mask will attribute rules 1,2,3,4,6 to the first thread, rules 5,7,8,9,10 to the second thread. 