#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "utils/Output.h"

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;

static void my_vmcall_callback(DECAF_Callback_Params* params) {
  int callnum = params->ie.env->regs[R_EAX];

  DECAF_printf("Got vmcall number %x!\n", callnum);
}

static int start_vmcall(void) {
  DECAF_printf("Starting vmcall_test...\n");

  vmcall_handle = DECAF_register_callback(DECAF_VMCALL_CB, &my_vmcall_callback,
                                         NULL);
  if (vmcall_handle == DECAF_NULL_HANDLE)
  {
    DECAF_printf("Could not register for the vmcall_CB\n");  
  }
  return (0);
}

static int stop_vmcall(void) {
  DECAF_printf("Stopping vmcall_test...\n");

  if (vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }
  return (0);
}

static void my_cleanup(void) {
  DECAF_printf("Unloading vmcall_test...\n");
  stop_vmcall();
} 

static mon_cmd_t my_term_cmds[] = {
  {
    .name           = "start_vmcall",
    .args_type      = "",
    .mhandler.cmd   = start_vmcall,
    .params         = "",
    .help           = "Start listening for vmcall callbacks"
  },
  {
    .name           = "stop_vmcall",
    .args_type      = "",
    .mhandler.cmd   = stop_vmcall,
    .params         = "",
    .help           = "Stop listening for vmcall callbacks"
  },
  {NULL, NULL, },
};

plugin_interface_t* init_plugin(void) {
  my_interface.mon_cmds = my_term_cmds;
  my_interface.plugin_cleanup = &my_cleanup;
  
  return (&my_interface);
}
