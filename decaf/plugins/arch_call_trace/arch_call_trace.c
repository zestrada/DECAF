#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_target.h"
#include "DECAF_callback_common.h"
#include "utils/Output.h"

/*
 * Plugin to provide a function call trace along with architectural operations
 * that occur inside each function
 */

//TODO:
//      1. On a call instruction: 
//        - Output full CPU state (general purpose+architectural)
//      2. On every instruction:
//        - check for architectural state changes and output if changed
//        - think about if this is really needed if we're already getting the
//          full state at each call
//        - Maybe look for interrupts/exceptions?
//        - Check for VMExit possibility (new callback?)

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_end_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];

static void insn_end_callback(DECAF_Callback_Params* params) {
	CPUState* env = NULL;
	if (!params) return;
	env = params->ib.env;
	if (!DECAF_is_in_kernel(env)) //only trace kernel for HW events
    return;
  //TODO: figure out how to write to a file, etc...
}

static void vmcall_callback(DECAF_Callback_Params* params) {
  int callnum = params->ie.env->regs[R_EAX];

  DECAF_printf("Got vmcall number %x!\n", callnum);
  if(callnum == 0) {
  /* start instruction tracing */
    if(trace_filename[0] == '\0') {
      DECAF_printf("Set filename first using command!\n");
      return;
    }   
    DECAF_printf("writing output to %s\n",trace_filename);
    insn_end_handle = DECAF_register_callback(DECAF_INSN_END_CB,
        insn_end_callback, NULL);
  } else if(callnum ==1) {
  /* stop instruction tracing */
		DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_handle);
  }

}

static void my_cleanup(void) {
  if (vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }

  if (insn_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_handle);
    insn_end_handle = DECAF_NULL_HANDLE;
  }
  DECAF_printf("plugin unloaded\n");
} 

void set_filename(Monitor *mon, const QDict *qdict) {
	const char* filename_str = qdict_get_str(qdict, "filepath");
  strncpy(trace_filename, filename_str, 128);
  DECAF_printf("set trace file to %s\n", trace_filename);
}

static mon_cmd_t my_term_cmds[] = {
{
	.name		= "set_filename",
  .args_type      = "filepath:F",
  .mhandler.cmd   = set_filename,
  .params         = "filepath",
  .help           = "start kernel trace on vmcall 0, stop on 1, saving into the specified file"
},
  {NULL, NULL, },
};

plugin_interface_t* init_plugin(void) {
  my_interface.mon_cmds = my_term_cmds;
  my_interface.plugin_cleanup = &my_cleanup;

  trace_filename[0]='\0';
  
  vmcall_handle = DECAF_register_callback(DECAF_VMCALL_CB, &vmcall_callback,
                                         NULL);
  if (vmcall_handle == DECAF_NULL_HANDLE) {
    DECAF_printf("Could not register for the vmcall_CB\n");  
  }

  return (&my_interface);
}
