#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_target.h"
#include "DECAF_callback_common.h"
#include "utils/Output.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

/*
 * Quick and dirty plugin to measure transition points from kernel into
 * userspace
 * Can either start/stop with vmcall to measure one workload or commands to
 * measure e.g., from boot
 * You'll get a couple of compiler warnings for the start_tracing and
 * stop_tracing functions since they are void but monitor commands
 */

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_end_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];
static FILE *tracefile;

static int was_in_kernel=1;
static target_ulong oldeip;

static void insn_end_callback(DECAF_Callback_Params* params) {
	CPUState* env = NULL;
	if(!params) return;
	env = params->ie.env;
  if(!env) {
    DECAF_printf("env is NULL!\n");
    return;
  }

  /*CPL lower 3 bits of selector in CS*/
	if((env->segs[R_CS].selector & 0x3)) {
    if(was_in_kernel) {
      fprintf(tracefile, "%x:\n", oldeip);
    }
    was_in_kernel=0;
  } else {
    was_in_kernel=1;
  } 
  oldeip=env->eip;

  return;
}

static void stop_tracing(void) {
  if(insn_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_handle);
    insn_end_handle = DECAF_NULL_HANDLE;
  }

  if(tracefile != NULL) {
    fclose(tracefile);
    tracefile=NULL;
  }
  
}

static void my_cleanup(void) {
  stop_tracing();
  if(vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }
} 

static void start_tracing(void) {
  /* start instruction tracing and initiliaze variables */
    if(trace_filename[0] == '\0') {
      DECAF_printf("Set filename first using command!\n");
      return;
    }   

    tracefile = fopen(trace_filename, "w");
    if(tracefile==NULL) {
      DECAF_printf("Couldn't open file %s: %s", trace_filename,
                   strerror(errno)); 
      return;
    }
    DECAF_printf("writing output to %s\n",trace_filename);
    insn_end_handle = DECAF_register_callback(DECAF_INSN_END_CB,
        insn_end_callback, NULL);
}

static void vmcall_callback(DECAF_Callback_Params* params) {
  int callnum; 
  if(!params)
    return;
  callnum = params->ie.env->regs[R_EAX];

  DECAF_printf("Got vmcall number %x!\n", callnum);
  if(callnum == 0) {
    start_tracing();
  } else {
    /* stop instruction tracing */
    stop_tracing();
  }
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
{
  .name   = "stop_tracing",
  .args_type  = "",
  .mhandler.info  = stop_tracing,
  .params   = "",
  .help   = "stop tracing"
},
{
  .name   = "start_tracing",
  .args_type  = "",
  .mhandler.info  = start_tracing,
  .params   = "",
  .help   = "start tracing"
},
  {NULL, NULL, },
};

plugin_interface_t* init_plugin(void) {
  my_interface.mon_cmds = my_term_cmds;
  my_interface.plugin_cleanup = &my_cleanup;

  trace_filename[0]='\0';
  tracefile=NULL;
  
  vmcall_handle = DECAF_register_callback(DECAF_VMCALL_CB, &vmcall_callback,
                                         NULL);
  if (vmcall_handle == DECAF_NULL_HANDLE) {
    DECAF_printf("Could not register for the vmcall_CB\n");  
  }

  return (&my_interface);
}
