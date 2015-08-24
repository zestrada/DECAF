#!/bin/bash

#I start my qemu (from decaf/) with these arguments:
# -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor 

SOCKET=../../monitor.sock

#Run a command in the qemu monitor
mon_cmd() {
  echo $1 | nc -U $SOCKET -q 0
}

mon_cmd 'unload_plugin'
mon_cmd 'load_plugin /mnt/usb/repos/DECAF/decaf/plugins/arch_call_trace/arch_call_trace.so'
mon_cmd "set_filename ${1}"
