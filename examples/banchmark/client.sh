#!/bin/bash
cd client
./client -limit 10 -addr 127.0.0.1:8000 -par 1 -head key=value -runtime 1000 -body 32
cd ..