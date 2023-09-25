#!/bin/bash
#starts the demo container, need privileged for tap/tun networking

docker run --rm -it --privileged \
    -v $(pwd)/share:/share \
    -p 4321:4321 \
    -p 8000:80 \
    -p 8444:443 \
    --name rehosting_demo \
    rehosting_demo \
    bash
