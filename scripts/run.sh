#!/bin/bash

# Den gewünschten Befehl hier definieren
COMMAND="./bin/python3 -m obstacle_bridge -c obstacle_bridge.cfg"

while true; do
  $COMMAND > /dev/null
  rc=$?
  if [ "$rc" -ne 75 ]; then
    exit "$rc"
  fi
done
