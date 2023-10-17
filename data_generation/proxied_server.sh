#!/bin/bash

(python3.9 -m http.server $1 --directory $2 --bind 127.0.0.1 &> /tmp/proxied.log) &
