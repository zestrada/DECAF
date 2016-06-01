#!/bin/bash

#I start my qemu (from decaf/) with these arguments:
# -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor 

SOCKET=../../monitor.sock

#Run a command in the qemu monitor
mon_cmd() {
  echo $1 | nc -U $SOCKET
}

mon_cmd 'unload_plugin'
mon_cmd 'load_plugin /home/zak/decaf_taint/decaf/plugins/keylogger/keylogger.so'
mon_cmd "enable_keylogger_check ${1}"
mon_cmd "taint_sendkey a"
