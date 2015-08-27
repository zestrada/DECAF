#!/bin/bash

#I start my qemu (from decaf/) with these arguments:
# -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor 

SOCKET=../../monitor.sock

#Run a command in the qemu monitor
mon_cmd() {
  echo $1 | nc -U $SOCKET -q 0
}

mon_cmd 'load_plugin /mnt/usb/repos/DECAF/decaf/plugins/tracecap_upstream/tracecap.so'
mon_cmd 'stop'
mon_cmd "trace_kernel ${1}"
mon_cmd 'stop'
