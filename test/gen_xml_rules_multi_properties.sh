#!/bin/bash

perl -pe 's/Clone_id /$& . ++$n/ge' properties_clone.xml > /tmp/prop.xml

perl -pe 's/property_id="/$& . ++$n/ge' /tmp/prop.xml > properties_clone_id.xml