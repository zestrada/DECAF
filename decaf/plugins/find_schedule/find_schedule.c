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

static target_ulong oldeip;
static unsigned last_sched;
static int get_next_instr;

static int found_sched_times; //by "times" I meant "count"
struct timeval last_sched_time, largest_deltat;

static unsigned find_function_header(CPUState *env, unsigned gva) {
  int i;
  int SEARCH_LEN=4096;
  uint8_t insns[SEARCH_LEN];

  DECAF_read_mem(env, (gva-SEARCH_LEN), SEARCH_LEN, insns);
  //Search backwards until we find a function protoype
  for(i=SEARCH_LEN-1;i>1;i--) {
    //push ebp; mov esp,ebp
    //55 89 e5
    if(insns[i]==0xe5 && insns[i-1]==0x89 && insns[i-2]==0x55) {
      fprintf(tracefile, "i: %d insns: %x\n",  i,
              (int)(insns[i] | ((int)insns[i-1]<<8) | ((int)insns[i-2]<<16)));
      return gva-SEARCH_LEN+i-2;
    }
  }
  return 0;
}

//copied from
//http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
static int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
 *      tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

#define FIND_SCHED_THRES 5

static void insn_end_callback(DECAF_Callback_Params* params) {
  unsigned char insn[MAX_INSN_BYTES];
  char outbuf[256];

  unsigned sched_addr;
  unsigned bytes;
  struct timeval now, deltat;
  xed_decoded_inst_t insn_decoded;
  xed_iclass_enum_t iclass; //class of the last executed instruction
  xed_operand_values_t ops;

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

  //iclass = xed_decoded_inst_get_iclass(&insn_decoded);

  /*write to cr3
  for movcr, mod=11 (register direct)
  so move to cr3 would always have 1101 1XXX & d8 == 1*/
  if(insn[0] ==  0x0f && insn[1] == 0x22 && ((insn[2] & 0xf8)==0xd8)) {
    ops = xed_decoded_inst_operands(&insn_decoded);
    sched_addr = find_function_header(env, env->eip);
    fprintf(tracefile, "calling function: %x\n", sched_addr);


    //We look to see if we've got this as the scheduler 5 times in a row
    //If so, it probably is? Crap heurestic, but can't argue with results

    if(sched_addr==last_sched)  {
      if(found_sched_times<FIND_SCHED_THRES)  {
        found_sched_times++;
      }
      found_sched_times=FIND_SCHED_THRES;//prevent overflow
    } else{
      if(found_sched_times<FIND_SCHED_THRES) {
        found_sched_times=0;
        last_sched=sched_addr;
      }
    }


    DECAF_read_mem(env, sched_addr, sizeof(bytes), &bytes);
    fprintf(tracefile, "read from %x: %x\n", sched_addr, bytes);
    if(xed_decoded_inst_dump_att_format(&insn_decoded, outbuf, 255, 0)) {
      outbuf[255]='\0'; 
      fprintf(tracefile, "%x: %s\n", env->eip, outbuf);
      fprintf(tracefile, "---\n");
    }
    fflush(tracefile);
  }

  /*Get monitoring threshhold by measuring largest gap from scheduler*/
  if(env->eip == last_sched && found_sched_times==FIND_SCHED_THRES) {
    if(last_sched_time.tv_sec!=0) {
      //At this point we're pretty sure we're in the actual scheduler
      gettimeofday(&now, NULL);

      timeval_subtract(&deltat, &now, &last_sched_time);

      if(deltat.tv_sec>largest_deltat.tv_sec) {
        largest_deltat = deltat;
      } else if(deltat.tv_sec==largest_deltat.tv_sec) {
        if(deltat.tv_usec>largest_deltat.tv_usec) {
          largest_deltat = deltat;
        }
      }

      fprintf(tracefile, "largest deltat: %ld.%06ld\n", 
             largest_deltat.tv_sec, largest_deltat.tv_usec);
      fflush(tracefile);
    }
    gettimeofday(&last_sched_time, NULL);
  }
  
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
  DECAF_stop_vm();
  get_next_instr = 0;
  found_sched_times = 0;
  count = 0;
  largest_deltat.tv_sec = 0;
  largest_deltat.tv_usec = 0;
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
  DECAF_start_vm();
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
