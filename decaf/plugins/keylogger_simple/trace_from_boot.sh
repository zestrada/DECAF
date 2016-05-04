#!/bin/bash

#I start my qemu (from decaf/) with these arguments:
# -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor 

SOCKET=../../winmonitor.sock

#Run a command in the qemu monitor
mon_cmd() {
  echo $1 | nc -U $SOCKET
}

mon_cmd 'unload_plugin'
mon_cmd 'load_plugin /home/zak/decaf/github/decaf/plugins/keylogger_simple/keylogger_simple.so'
mon_cmd "set_filename ${1}"
mon_cmd "start_tracing"
