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
#include <xed-interface.h>

/*
 * Plugin to provide a function call trace along with architectural operations
 * that occur inside each function.  Heavily inspired by tracecap, but I'm
 * hoping that we can work with a simpler subset of functionality. Otherwise,
 * I'll port these checks over to a forked version of that plugin
 *
 * NOTE: this is not thread safe in the least bit!
 */

#define MAX_INSN_BYTES 15 /* Maximum number of bytes in a x86 instruction */
#define MAX_STR_LEN 15 /* Maximum number of bytes in a x86 instruction */

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_end_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];
static FILE *tracefile;
static CPUState last_state;
static int insn_count; //Instructions we've seen since the trace started

/*Macros that will be used for checking and printing hardware state*/
//I know memcmp isn't the best, but we will filter any false positives later
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
        fprintf(tracefile, "\"%s\": \"0x%x\"", name, value); \
        if(comma) fprintf(tracefile, ", ");
#define JSON_INT(name, value, comma) \
        fprintf(tracefile, "\"%s\": %d", name, value); \
        if(comma) fprintf(tracefile, ", ");
        
//Lazy copy+paste refactor if it needs to change again!
#define JSON_U64HEX(name, value, comma) \
        fprintf(tracefile, "\"%s\": \"0x%" PRIx64 "\"", name, value); \
        if(comma) fprintf(tracefile, ", ");

#define JSON_SEGMENT(seg, outname) \
        fprintf(tracefile, "\"%s\": { \"selector\": \"0x%x\", ", \
                outname, seg.selector); \
        JSON_HEX("base", seg.base, true) \
        JSON_HEX("limit", seg.limit, true) \
        JSON_HEX("flags", seg.flags, false) \
        fprintf(tracefile, "}");

#define JSON_ARRAY(array, outname) \
        fprintf(tracefile, "\"%s\": [", outname); \
        for(i=0; i<COUNT_OF(array); i++) {\
           fprintf(tracefile, "\"0x%x\"", array[i]); \
           if(i<COUNT_OF(array)-1) \
             fprintf(tracefile, ", "); \
        } \
        fprintf(tracefile, "]");

#define JSON_U64ARRAY(array, outname) \
        fprintf(tracefile, "\"%s\": [", outname); \
        for(i=0; i<COUNT_OF(array); i++) {\
           fprintf(tracefile, "\"0x%" PRIx64 "\"", array[i]); \
           if(i<COUNT_OF(array)-1) \
             fprintf(tracefile, ", "); \
        } \
        fprintf(tracefile, "]");

/*These are the classes of instruction that we care about */
/*TODO: convert to array with enums*/
struct insn_table {
  int wait;
  int call_far_ptrp_immw;
  int call_far_memp2;
  int call_near_memv;
  int call_near_relbrd;
  int call_near_relbrz;
  int call_near_gprv;
  int sysexit; //actually sysret too
  /*Was originally going to combine some of these, but we can do that in post
   * processing*/
  int jb;
  int jbe;
  int jl;
  int jle;
  int jmp;
  int jmp_far;
  int jnb;
  int jnbe;
  int jnl;
  int jnle;
  int jno;
  int jnp;
  int jns;
  int jnz;
  int jo;
  int jp;
  int jrcxz;
  int js;
  int jz;
  int last_invalid;
} insn_table;

struct insn_table insn_table_zeros;

/*Takes the iform for our instruction and a list of other iforms count long
 * return 1 if any match, 0 if not
 */
int matchesform(xed_iform_enum_t iform, int count, ...) {
  va_list args;
  int i;

  va_start(args, count);

  for(i=0; i<count; i++) {
    if(iform == va_arg(args, xed_iform_enum_t))
      return 1;
  }

  return 0;
}

/*Same as above, but iclass. Didn't want to do evil casting. Feel free to
 * refactor
 */
int matchesclass(xed_iclass_enum_t iclass, int count, ...) {
  va_list args;
  int i;

  va_start(args, count);

  for(i=0; i<count; i++) {
    if(iclass == va_arg(args, xed_iclass_enum_t))
      return 1;
  }

  return 0;
}


/*This is the check to see if architectural state has been modified since the
 *last instruction or check the opcode if the particular instruction is known to 
 *modify state
 *NOTE that we do lazy evaluation. An implicit assumption is that one 
 * instruction will only affect one of these things at at time
 *this may not be valid, so we could switch to the more expensive thing...
 */
static int insn_affects_state(CPUState *env, unsigned char *insn) {
  int i; //general iterator used by macros!
  xed_decoded_inst_t insn_decoded;
  xed_iform_enum_t iform; //form of the last executed instruction
  xed_iclass_enum_t iclass; //class of the last executed instruction

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

  /*Check instruction opcode using the xed library*/
  xed_decoded_inst_zero(&insn_decoded);
  xed_decoded_inst_set_mode(&insn_decoded, XED_MACHINE_MODE_LEGACY_32,
                            XED_ADDRESS_WIDTH_32b);
  xed_decode(&insn_decoded, (const xed_uint8_t *) insn, 15);
  memset(&insn_table, 0x0, sizeof(insn_table));

  /*Check by iform*/
  iform = xed_decoded_inst_get_iform_enum(&insn_decoded);
  insn_table.wait = matchesform(iform, 2, XED_IFORM_MWAIT, XED_IFORM_FWAIT);
  insn_table.call_far_ptrp_immw = matchesform(iform, 1,
                                              XED_IFORM_CALL_FAR_PTRp_IMMw);
  insn_table.call_far_memp2 = matchesform(iform, 1, XED_IFORM_CALL_FAR_MEMp2);
  insn_table.call_near_memv = matchesform(iform, 1, XED_IFORM_CALL_NEAR_MEMv);
  insn_table.call_near_relbrd = matchesform(iform, 1, 
                                            XED_IFORM_CALL_NEAR_RELBRd);
  insn_table.call_near_relbrz = matchesform(iform, 1,
                                            XED_IFORM_CALL_NEAR_RELBRz);
  insn_table.call_near_gprv = matchesform(iform, 1, XED_IFORM_CALL_NEAR_GPRv);
  insn_table.sysexit = matchesform(iform, 2, XED_IFORM_SYSEXIT, 
                                   XED_IFORM_SYSRET);

  /*Check by iclass*/
  iclass  = xed_iform_to_iclass(iform);
  insn_table.jb = matchesclass(iclass, 1, XED_ICLASS_JB);
  insn_table.jbe = matchesclass(iclass, 1, XED_ICLASS_JBE);
  insn_table.jl = matchesclass(iclass, 1, XED_ICLASS_JL);
  insn_table.jle = matchesclass(iclass, 1, XED_ICLASS_JLE);
  insn_table.jmp = matchesclass(iclass, 1, XED_ICLASS_JMP);
  insn_table.jmp_far = matchesclass(iclass, 1, XED_ICLASS_JMP_FAR);
  insn_table.jnb = matchesclass(iclass, 1, XED_ICLASS_JNB);
  insn_table.jnbe = matchesclass(iclass, 1, XED_ICLASS_JNBE);
  insn_table.jnl = matchesclass(iclass, 1, XED_ICLASS_JNL);
  insn_table.jnle = matchesclass(iclass, 1, XED_ICLASS_JNLE);
  insn_table.jno = matchesclass(iclass, 1, XED_ICLASS_JNO);
  insn_table.jnp = matchesclass(iclass, 1, XED_ICLASS_JNP);
  insn_table.jns = matchesclass(iclass, 1, XED_ICLASS_JNS);
  insn_table.jnz = matchesclass(iclass, 1, XED_ICLASS_JNZ);
  insn_table.jo = matchesclass(iclass, 1, XED_ICLASS_JO);
  insn_table.jp = matchesclass(iclass, 1, XED_ICLASS_JP);
  insn_table.jrcxz = matchesclass(iclass, 1, XED_ICLASS_JRCXZ);
  insn_table.js = matchesclass(iclass, 1, XED_ICLASS_JS);
  insn_table.jz = matchesclass(iclass, 1, XED_ICLASS_JZ);

  /*If we got any 1s we have a change*/ 
  CHECK_STRUCT(&insn_table, &insn_table_zeros);

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
  fprintf(tracefile, "{ \"insn_count\": %d, \"eip\": \"0x%x\", ",
                     insn_count, env->eip);

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
  fprintf(tracefile, "\"exception\": {"); 
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
    fprintf(tracefile,
            "{\"base\": \"0x%" PRIx64"\", \"mask\": \"0x%" PRIx64"\"}",
            env->mtrr_var[i].base, env->mtrr_var[i].mask);
    if(i<COUNT_OF(env->mtrr_var)-1) fprintf(tracefile, ", ");
  }
  fprintf(tracefile, "], ");
  JSON_U64HEX("xcr0", env->xcr0, true)

  /*When outputting instructions, we'll just use boolean values*/
  //TODO: JSON TABLE FOR INSTRUCTIONS OF INTEREST? 
  fprintf(tracefile, "\"instructions\": {"); 
    JSON_INT("wait", insn_table.wait, true)
    JSON_INT("call_far_ptrp_immw", insn_table.call_far_ptrp_immw, true);
    JSON_INT("call_far_memp2", insn_table.call_far_memp2, true);
    JSON_INT("call_near_memv", insn_table.call_near_memv, true);
    JSON_INT("call_near_relbrd", insn_table.call_near_relbrd, true);
    JSON_INT("call_near_relbrz", insn_table.call_near_relbrz, true);
    JSON_INT("call_near_gprv", insn_table.call_near_gprv, true);
    JSON_INT("sysexit", insn_table.sysexit, true);
    JSON_INT("jb", insn_table.jb, true);
    JSON_INT("jbe", insn_table.jbe, true);
    JSON_INT("jl", insn_table.jl, true);
    JSON_INT("jle", insn_table.jle, true);
    JSON_INT("jmp", insn_table.jmp, true);
    JSON_INT("jmp_far", insn_table.jmp_far, true);
    JSON_INT("jnb", insn_table.jnb, true);
    JSON_INT("jnbe", insn_table.jnbe, true);
    JSON_INT("jnl", insn_table.jnl, true);
    JSON_INT("jnle", insn_table.jnle, true);
    JSON_INT("jno", insn_table.jno, true);
    JSON_INT("jnp", insn_table.jnp, true);
    JSON_INT("jns", insn_table.jns, true);
    JSON_INT("jnz", insn_table.jnz, true);
    JSON_INT("jo", insn_table.jo, true);
    JSON_INT("jp", insn_table.jp, true);
    JSON_INT("jrcxz", insn_table.jrcxz, true);
    JSON_INT("js", insn_table.js, true);
    JSON_INT("jz", insn_table.jz, false);
  fprintf(tracefile, "}");

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
    insn_count=-1;
    memset(&insn_table, 0x0, sizeof(insn_table));
    /* didn't do C99 'struct = {0}' in case padding ends up being weird */
    memset(&insn_table_zeros, 0x0, sizeof(insn_table));
    //FIXME: write state here so that we have an immediate reference?   
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

  /*instruction decoding stuff*/
  xed_tables_init();

  return (&my_interface);
}
