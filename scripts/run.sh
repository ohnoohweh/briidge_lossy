#!/bin/bash

# Den gewünschten Befehl hier definieren
COMMAND="./bin/python3 -m obstacle_bridge -c obstacle_bridge.cfg"

until [ $? -eq 75 ]; do
  $COMMAND > /dev/null
done
