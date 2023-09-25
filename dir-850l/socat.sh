#!/bin/bash
socat TCP-LISTEN:80,fork TCP:192.168.0.1:80
