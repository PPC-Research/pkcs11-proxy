#!/usr/bin/env bash

tshark -r $1 -q -z conv,tcp
tshark -r $1 -d tcp.port==2345,tls -Y tls -c 25 -nn \
-o gui.column.format:"No.","%m",\
"Time","%t",\
"Source","%s",\
"SrcPort","%uS",\
"Destination","%d",\
"DstPort","%uD",\
"Protocol","%p",\
"Length","%L",\
"Info","%i"
echo "-------------------------"
tshark -r $1 -d tcp.port==2345,tls -Y "tls.handshake" -V | grep -i -E "psk|identity"
echo "-------------------------"
tshark -r "$1" \
  -d tcp.port==2345,tls \
  -Y "tls.handshake.type == 16" \
  -T fields \
  -e frame.number \
  -e tls.handshake.identity \
| while read f id; do
    clean=$(echo "$id" | tr -d ':')
    ascii=$(echo "$clean" | xxd -r -p )
    echo "Identity -> Hex: $clean | ASCII: $ascii"
  done
