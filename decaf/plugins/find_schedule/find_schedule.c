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
#include <xed-interface.h>

/*
 * Quick and dirty plugin to locate the scheduler function and 
 * also bound it to determine a maximum detection latency
 */


xed_uint_t insn_len;
#define MAX_INSN_BYTES 15 /* Maximum number of bytes in a x86 instruction */

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_end_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];
static FILE *tracefile;
static uint count;

static int was_in_kernel=1;
static target_ulong oldeip;

static void insn_end_callback(DECAF_Callback_Params* params) {
  xed_decoded_inst_t insn_decoded;
  xed_iclass_enum_t iclass; //class of the last executed instruction
  unsigned char insn[MAX_INSN_BYTES];
  char outbuf[256];

	CPUState* env = NULL;
	if(!params) return;
	env = params->ie.env;
  if(!env) {
    DECAF_printf("env is NULL!\n");
    return;
  }

  if(!DECAF_is_in_kernel(env))
    return;

  count++;

  DECAF_read_mem(env, env->eip, MAX_INSN_BYTES, insn);

  xed_decoded_inst_zero(&insn_decoded);
  xed_decoded_inst_set_mode(&insn_decoded, XED_MACHINE_MODE_LEGACY_32,
                            XED_ADDRESS_WIDTH_32b);
  xed_decode(&insn_decoded, (const xed_uint8_t *) insn, MAX_INSN_BYTES);
  insn_len = xed_decoded_inst_get_length(&insn_decoded);
  insn_len = insn_len > MAX_INSN_BYTES ? MAX_INSN_BYTES : insn_len;

  iclass = xed_decoded_inst_get_iclass(&insn_decoded);

  if(iclass == XED_ICLASS_MOV_CR) {
    if(xed_decoded_inst_dump_att_format(&insn_decoded, outbuf, 255, 0)) {
      outbuf[255]='\0'; 
      fprintf(tracefile, "%x: %s\n", env->eip, outbuf);
      fflush(tracefile);
    }
  }
  /*
  if(iclass == XED_ICLASS_CALL_NEAR) {
  
  }
  */

  /*
  if(env->eip == 0xc146baa0) {
    fprintf(tracefile, "%x\n", env->eip);
    fflush(tracefile);
  }
  */

  return;
}

static void stop_tracing(void) {
  DECAF_stop_vm();
  if(insn_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_handle);
    insn_end_handle = DECAF_NULL_HANDLE;
  }

  if(tracefile != NULL) {
    fclose(tracefile);
    tracefile=NULL;
  }
  DECAF_start_vm();
}

static void my_cleanup(void) {
  stop_tracing();
  if(vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }
} 

static void start_tracing(void) {
  count = 0;
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
  xed_tables_init();
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
