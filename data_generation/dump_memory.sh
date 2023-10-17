#!/bin/bash

ps_list=$(pgrep $1)
mkdir -p memory_dump

for pid in $ps_list; do
  mkdir -p "$2/$pid"
  command_name=$(ps -q $pid -o command=)
  echo $command_name > "$2/$pid/info.txt"

  cat /proc/$pid/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
      gdb --batch --pid $pid -ex \
        "dump memory $2/$pid/$start-$stop.dump 0x$start 0x$stop"; \
    done
done

