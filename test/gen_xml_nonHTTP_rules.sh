#!/bin/bash

if [ $# -ne 2 ]; then
   echo "Usage: ./$0 from to"
   exit 1
fi

TO=$2

echo "<beginning>"

COUNTER=$1
while [ $COUNTER -le $TO  ]; do
   echo "<!-- Property $COUNTER -->"
 
PROPERTY=$(cat <<-END

<property value="THEN" delay_units="s" delay_min="0" delay_max="0" property_id="$COUNTER" type_property="EVASION" 
    description="C4_Analyse_03h: The minimum size of an IP fragment is 28 bytes and for an IP fragment with offset 0 it is 40.">
    <event value="COMPUTE" event_id="1" 
           description="IP segment and paquet size"
           boolean_expression="((ip.mf_flag &gt; 0)&amp;&amp;((ip.tot_len &lt; 28)||((ip.frag_offset == 0)&amp;&amp;(ip.tot_len &lt; 40))))"/>
    <event value="COMPUTE" event_id="2" 
           description="IP segment"
           boolean_expression="(ip.src != ip.dst)"/>
</property>

END
)
   
   echo $PROPERTY

   let COUNTER+=1
done

echo "</beginning>"