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
    description="C4_Analyse_03f : HTTP using a port different from 80 and 8080.">
    <event value="COMPUTE" event_id="1" 
        description="HTTP packet using a port different from 80 and 8080"
           boolean_expression="(( http.method != '') &amp;&amp;((tcp.dest_port != 80)&amp;&amp;(tcp.dest_port != 8080)))"/>
    <event value="COMPUTE" event_id="2" 
           description="HTTP packet"
           boolean_expression="(ip.src != ip.dst)"/>
   </property>

END
)
   
   echo $PROPERTY

   let COUNTER+=1
done

echo "</beginning>"