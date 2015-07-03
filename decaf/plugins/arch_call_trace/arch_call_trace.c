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
 * Plugin to provide a function call trace along with architectural operations
 * that occur inside each function.  Heavily inspired by tracecap, but I'm
 * hoping that we can work with a simpler subset of functionality. Otherwise,
 * I'll port these checks over to a forked version of that plugin
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
#define MAX_INSN_BYTES 15 /* Maximum number of bytes in a x86 instruction */

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_end_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];
static FILE *tracefile;
static CPUState last_state;
static int insn_count; //Instructions we've seen since the trace started

/*Macros that will be used for checking and printing hardware state*/
//TODO: is padding 0 or will this just blow up?
#define CHECK_STRUCT(s1, s2) \
        if(memcmp((const void *) s1, (const void *) s2, sizeof(s1))) return 1;
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
#define CHECK_ARRAY(a1, a2 ) \
        for(i=0; i<COUNT_OF(a1); i++) { if(a1[i]!=a2[i]) return 1; }
#define CHECK_STRUCT_ARRAY(a1, a2 ) \
        for(i=0; i<COUNT_OF(a1); i++) { CHECK_STRUCT(&a1[i], &a2[i]) }

//TODO: fix earlier macros to match this style
#define CHECK_FIELD(field) if(env->field != last_state.field) return 1;

//Kinda overkill, but hey
#define JSON_HEX(name, value, comma) \
        fprintf(tracefile, "\"%s\": 0x%x", name, value); \
        if(comma) fprintf(tracefile, ", ");
        
//Lazy copy+paste refactor if it needs to change again!
#define JSON_U64HEX(name, value, comma) \
        fprintf(tracefile, "\"%s\": 0x%" PRIx64 "", name, value); \
        if(comma) fprintf(tracefile, ", ");

#define JSON_SEGMENT(seg, outname) \
        fprintf(tracefile, "\"%s\": { \"selector\": %x, ", \
                outname, seg.selector); \
        JSON_HEX("base", seg.base, true) \
        JSON_HEX("limit", seg.limit, true) \
        JSON_HEX("flags", seg.flags, true) \
        fprintf(tracefile, "}");

#define JSON_ARRAY(array, outname) \
        fprintf(tracefile, "\"%s\": [", outname); \
        for(i=0; i<COUNT_OF(array); i++) {\
           fprintf(tracefile, "0x%x", array[i]); \
           if(i<COUNT_OF(array)-1) \
             fprintf(tracefile, ", "); \
        } \
        fprintf(tracefile, "]");

#define JSON_U64ARRAY(array, outname) \
        fprintf(tracefile, "\"%s\": [", outname); \
        for(i=0; i<COUNT_OF(array); i++) {\
           fprintf(tracefile, "0x%" PRIx64 "", array[i]); \
           if(i<COUNT_OF(array)-1) \
             fprintf(tracefile, ", "); \
        } \
        fprintf(tracefile, "]");
/*This is the check to see if architectural state has been modified since the
 *last instruction or check the opcode if the particular instruction is known to *modify state
 */
//TODO: will we discover all exceptions here?
static int insn_affects_state(CPUState *env, unsigned char *insn) {
  int i; //general iterator used by macros!

  /*Standard x86 specific state*/
  CHECK_STRUCT(&env->ldt, &last_state.ldt) //Check LDTR
  CHECK_STRUCT(&env->tr, &last_state.tr) //Check TR
  CHECK_STRUCT(&env->gdt, &last_state.gdt) //Check GDTR
  CHECK_STRUCT(&env->idt, &last_state.idt) //Check IDTR
  CHECK_ARRAY(env->cr, last_state.cr) //Check CRs
  CHECK_STRUCT_ARRAY(env->segs, last_state.segs) //Check segment registers

  /*Exceptions*/
  if(!env->exception_is_int) { //For now, ignore interrupts
    CHECK_FIELD(exception_index)
    CHECK_FIELD(error_code)
  }

  /*Misc Memory Things*/
  CHECK_ARRAY(env->mtrr_fixed, last_state.mtrr_fixed)
  CHECK_STRUCT_ARRAY(env->mtrr_var, last_state.mtrr_var)
  CHECK_FIELD(mtrr_deftype) //Page attribute table
  CHECK_FIELD(pat) //Page attribute table
  CHECK_FIELD(xcr0) 


  /*Check instruction opcode*/
  //TODO think of instructions: mwait, invlpg, etc...

  return 0;
}

/*These are taken from target-i386/cpu.h and used to identify the segment regs!
 *ensure these are consistent if porting to a new version!
 *#define R_ES 0
 *#define R_CS 1
 *#define R_SS 2
 *#define R_DS 3
 *#define R_FS 4
 *#define R_GS 5
 */
const char seg_names[6][3] = {"ES", "CS", "SS", "DS", "FS", "GS"};
/* output state in JSON format for easy parsing */
static void write_state(CPUState *env) {
  //TODO: we may need to use synchronization methods, but here I'm assuming
  //      single threaded
  if(tracefile==NULL)
    return;
  int i; //iterator used by macros!
  fprintf(tracefile, "(%d) 0x%x: {", insn_count, env->eip);

  /*Standard x86 specific state*/
  JSON_ARRAY(env->cr, "CR")
  fprintf(tracefile, ", ");
  JSON_SEGMENT(env->ldt, "LDT")
  fprintf(tracefile, ", ");
  JSON_SEGMENT(env->tr, "TR")
  fprintf(tracefile, ", ");
  JSON_SEGMENT(env->idt, "IDTR")
  fprintf(tracefile, ", ");
  JSON_SEGMENT(env->gdt, "GDTR")
  for(i=0; i<6; i++) {
    fprintf(tracefile, ", ");
    JSON_SEGMENT(env->segs[i], seg_names[i])
  }

  /*Exception handling stuff*/
  fprintf(tracefile, ", ");
  fprintf(tracefile, "\"exception:\" {"); 
  {
    JSON_HEX("index", env->exception_index, true)
    JSON_HEX("error_code", env->error_code, false)
  }
  fprintf(tracefile, "}, ");

  /*Misc Memory Things*/
  JSON_U64HEX("pat", env->pat, true)
  JSON_U64ARRAY(env->mtrr_fixed, "mtrr_fixed")
  fprintf(tracefile, ", \"mtrr_var\": [");
  for(i=0; i<COUNT_OF(env->mtrr_var); i++) {
    fprintf(tracefile, "{\"base\": %" PRIx64", \"mask\": %" PRIx64"}",
                       env->mtrr_var[i].base, env->mtrr_var[i].mask);
    if(i<COUNT_OF(env->mtrr_var)-1) fprintf(tracefile, ", ");
  }
  fprintf(tracefile, "], ");
  JSON_HEX("xcr0", env->xcr0, false)

  /*When outputting instructions, we'll just use binary*/

  //END
  fprintf(tracefile, "}\n");
}

/* check for function call */
//TODO: for now, we don't need this. We'll do this if we need to track data
//structs. We can then track them using args and ctags/dwarf info
static int is_call(unsigned char *insn) {
  //used this site a reference:
  //http://x86.renejeschke.de/html/file_module_x86_id_26.html 
  return 1;
}

static void insn_end_callback(DECAF_Callback_Params* params) {
	CPUState* env = NULL;
  unsigned char insn[MAX_INSN_BYTES];
	if(!params) return;
	env = params->ie.env;
  if(!env) {
    DECAF_printf("env is NULL!\n");
    return;
  }

  DECAF_read_mem(env, env->eip, MAX_INSN_BYTES, insn);

	if(!DECAF_is_in_kernel(env)) //only trace kernel for HW events
    goto ie_out;

  /* First instruction is counted as -1 */
  if(insn_count<0)
    goto ie_output;

  /*stop if architectural state is the same*/
  if(!insn_affects_state(env, insn))
    goto ie_out;

  if(!is_call(insn))
    goto ie_out;
    
  //we've now written the PC, so we can use System.map to bound the function
  //TODO: print out state that changed? (is this important right now)
  ie_output:
    write_state(env);
    last_state = *env; 

  ie_out: 
    insn_count++;
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
  
  insn_count=-1;
}

static void my_cleanup(void) {
  stop_tracing();
  if(vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }
} 

static void vmcall_callback(DECAF_Callback_Params* params) {
  int callnum; 
  if(!params)
    return;
  callnum = params->ie.env->regs[R_EAX];

  DECAF_printf("Got vmcall number %x!\n", callnum);
  if(callnum == 0) {
  /* start instruction tracing */
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
    insn_count=-1;
    insn_end_handle = DECAF_register_callback(DECAF_INSN_END_CB,
        insn_end_callback, NULL);
  } else if(callnum ==1) {
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
