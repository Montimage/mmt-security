
This document explains how we can find quickly a set of rules to verify when we know a `message_t`.
We know that a rule contains a set of events. Each event contains a set of proto.att.
A rule is verified when we have a `message_t` that contains at least one event.

## Problem statement

Let examine the following rule:

```xml
<property value="THEN" delay_units="s" delay_min="0+" delay_max="6" property_id="3" type_property="ATTACK" 
    description="TCP SYN requests on microsoft-ds port 445 with SYN ACK.">
    <event value="COMPUTE" event_id="1"
           description="SYN request"
           boolean_expression="((tcp.flags == 2)&amp;&amp;(tcp.dest_port == 445))"/>
    <event value="COMPUTE" event_id="2" 
           description="SYN ACK reply"
           boolean_expression="((tcp.flags == 18)&amp;&amp;(ip.src == ip.dst.1))"/>
</property>
```

This rule has 2 events. 
The first event, having `event_id=1`, requires the present of `tcp.flags`, `tcp.dest_port`  and `ip.dst` (it will be used in event 2).
The second one requires `tcp.flags`, `ip.src`.
This rule is verified against a message `msg` if the message contains:

- either `set_1` = ( `tcp.flags`, `tcp.dest_port`, `ip.dst`)
- or `set_2` = (`tcp.flags`, `ip.src`)
- or `set_3` = `set_1` v `set_2`

Thus, given a message `msg` having a set of proto.atts. We need to find the fastest way to get a set of rules
that will be verified against `msg`.

## Solution

We create a tree containing all possible of