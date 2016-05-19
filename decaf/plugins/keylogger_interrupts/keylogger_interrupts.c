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
#include <pthread.h>

#ifdef CONFIG_VMI_ENABLE
#include "vmi_callback.h"
#include "vmi_c_wrapper.h"
#endif //CONFIG_VMI_ENABLE

/*
 * Try to identify the functions used by keyboard handling for live keylogger
 * detection
 */

static plugin_interface_t my_interface;
static DECAF_Handle vmcall_handle = DECAF_NULL_HANDLE;
static DECAF_Handle keystroke_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_end_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle interrupt_handle = DECAF_NULL_HANDLE;
static char trace_filename[128];
static FILE *tracefile;
static uint32_t last_cr3 = 0x0;
static int was_int;
static int use_sysenter = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//note that this may cause problems with CONFIG_TCG_TAINT enabled
static int keystroke_enabled = 1;

//We'll print the last few calls after a keystroke
#define MAXCALLS 20
static uint calls = MAXCALLS;

void check_call(DECAF_Callback_Params *param) {
  uint32_t eip, cr3, insn_buf;
  CPUState *env = NULL;

  //If we've gotten this far, params is not null
  if(calls<MAXCALLS) {
    env = param->be.env;
    if(env!=NULL) {
      eip=DECAF_getPC(env);
      cr3=DECAF_getPGD(env);
    } else {
      eip=0x0;
      cr3=0x0;
    }

    DECAF_printf("sysenter_eip: (0x%x)\n", env->sysenter_eip);
    fprintf(tracefile, "sysenter_eip: (0x%x)\n", env->sysenter_eip);
    fprintf(tracefile, "sysenter_esp: (0x%x)\n", env->sysenter_esp);
    fprintf(tracefile, "current esp: (0x%x)\n", env->regs[R_ESP]-env->sysenter_eip);
    //fprintf(tracefile, "idt base: (0x%x) \n", env->idt.base); 

    //Read 32bits worth of code... will be used to identify this later
    DECAF_read_mem(env,param->be.cur_pc,sizeof(uint32_t),&insn_buf);
    DECAF_printf("call: (0x%x@0x%x) 0x%x\n", eip-env->sysenter_eip, cr3, insn_buf);
    fprintf(tracefile, "call: (0x%x@0x%x) 0x%x\n", eip-env->sysenter_eip, cr3,
            insn_buf);
    fprintf(tracefile, "call (-esp): (0x%x@0x%x) 0x%x\n", eip-env->sysenter_esp, 
            cr3, insn_buf);
    calls++;
  }
}

//Cheap copy+paste: do the same as calls, but don't print
void check_ret(DECAF_Callback_Params *param) {
  uint32_t eip, cr3;
  CPUState *env = NULL;

  //If we've gotten this far, params is not null
  if(calls<MAXCALLS) {
    env = param->be.env;
    if(env!=NULL) {
      eip=DECAF_getPC(env);
      cr3=DECAF_getPGD(env);
    } else {
      eip=0x0;
      cr3=0x0;
    }

    DECAF_printf("ret: (0x%x@0x%x)\n", eip-env->sysenter_eip, cr3);
    fprintf(tracefile, "ret: (0x%x@0x%x)\n", eip-env->sysenter_eip, cr3);
  }
}

void check_sysenter(DECAF_Callback_Params *param) {
  fprintf(tracefile, "sysenter instruction: eax: 0x%x\n", 
          param->be.env->regs[R_EAX]);
}

void block_begin_callback(DECAF_Callback_Params *param) {
  uint32_t address;
  if(param==NULL) {
    DECAF_printf("Null params!\n");
    return;
  }
  pthread_mutex_lock(&mutex);
  if(was_int) {
    address = param->bb.env->eip;
    if(use_sysenter)
      address -= param->bb.env->sysenter_eip;
    //fprintf(tracefile, "eip: %x:\n", address);
    was_int--;
  }
  pthread_mutex_unlock(&mutex);
}

/*Taken and modified from the original keylogger example */
void block_end_callback(DECAF_Callback_Params *param)
{
	unsigned char insn_buf[2];
	int is_call = 0, is_ret = 0, is_sysenter = 0;
	int b, cpl;
  uint32_t cr3, eip;
#ifdef CONFIG_VMI_ENABLE
	char name[128];
	tmodinfo_t dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
#endif //CONFIG_VMI_ENABLE

  pthread_mutex_lock(&mutex);
	DECAF_read_mem(param->be.env,param->be.cur_pc,sizeof(char)*2,insn_buf);

	switch(insn_buf[0]) {
		case 0x9a:
		case 0xe8:
		is_call = 1;
		break;
		case 0xff:
		b = (insn_buf[1]>>3) & 7;
		if(b==2 || b==3)
		is_call = 1;
		break;

		case 0xc2:
		case 0xc3:
		case 0xca:
		case 0xcb:
		is_ret = 1;
		break;

    case 0x0f:
		if(insn_buf[1]==0x34)
      is_sysenter = 1;
    break;
		default: break;
	}

	/*
	 * Handle both the call and the return
	 */
	if (is_call)
    check_call(param); //TODO: clean up redundancies here
  else if (is_ret)
    check_ret(param);
/*
  else if (is_sysenter)
    check_sysenter(param);
*/

  cr3 = DECAF_getPGD(param->be.env);
  if( cr3 != last_cr3) {
    eip=DECAF_getPC(param->be.env);
    cpl=param->be.env->segs[R_CS].selector & 0x3;
    DECAF_printf("BE - New cr3: 0x%x\n", cr3);
    fprintf(tracefile, "BE - New cr3: 0x%x CPL: %d ", cr3, cpl);
#ifdef CONFIG_VMI_ENABLE
    if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
    {
      strcpy(name, "<None>");
      bzero(&dm, sizeof(dm));
    }
    name[127]= '\0';
    fprintf(tracefile, "%s ",name);
#endif //CONFIG_VMI_ENABLE
    fprintf(tracefile, "eip: 0x%x\n", eip-param->be.env->sysenter_eip);
    fflush(tracefile);
    last_cr3 = cr3;
  }

  pthread_mutex_unlock(&mutex);
}

static void keystroke_callback(DECAF_Callback_Params* params) {
  int keycode;

	if(!params) {
   DECAF_printf("Keystroke callback with NULL params!\n");
   return;
  }

  pthread_mutex_lock(&mutex);
  keycode = params->ks.keycode;
  DECAF_printf("keystroke: %x\n", keycode);
  fprintf(tracefile, "keystroke: %x\n", keycode);
  calls = 0;
  pthread_mutex_unlock(&mutex);
}

static void interrupt_callback(DECAF_Callback_Params* params) {
  int intno;
  CPUState *env;
  uint32_t isr_address;
  uint64_t gate_entry;

	if(!params) {
   DECAF_printf("Interrupt callback with NULL params!\n");
   return;
  }
 
  intno = params->it.intno; 
  if(params->it.is_hw)  {
    env = params->it.env;
    //Now get the ISR from the IDT
    isr_address = env->idt.base + intno*8; //reusing this variable for the entry
    DECAF_read_mem(env,isr_address,sizeof(gate_entry),&gate_entry);
    isr_address = (gate_entry>>32ULL & 0xffff0000) | (gate_entry & 0x0000ffff);
    fprintf(tracefile, "HW Interrupt: 0x%x, handler: 0x%x, "
                       "sysenter_eip offset: 0x%x\n", intno, isr_address,
                       isr_address-env->sysenter_eip);
  }
  pthread_mutex_lock(&mutex);
  was_int = MAXCALLS;
  pthread_mutex_unlock(&mutex);
}
static void stop_tracing(void) {
  DECAF_stop_vm();

  if(keystroke_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_KEYSTROKE_CB, keystroke_handle);
    keystroke_handle = DECAF_NULL_HANDLE;
  }

  if(block_end_handle != DECAF_NULL_HANDLE) {
    DECAF_unregisterOptimizedBlockEndCallback(block_end_handle);
    block_end_handle = DECAF_NULL_HANDLE;
  }

  if(block_begin_handle != DECAF_NULL_HANDLE) {
    DECAF_unregisterOptimizedBlockBeginCallback(block_begin_handle);
    block_begin_handle = DECAF_NULL_HANDLE;
  }

  if(interrupt_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INTR_CB, interrupt_handle);
    interrupt_handle = DECAF_NULL_HANDLE;
  }
  if(tracefile != NULL) {
    fclose(tracefile);
    tracefile=NULL;
  }
  DECAF_start_vm();
}

static void my_cleanup(void) {
  stop_tracing();
  DECAF_stop_vm();
  if(vmcall_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_VMCALL_CB, vmcall_handle);
    vmcall_handle = DECAF_NULL_HANDLE;
  }
  DECAF_start_vm();
} 

static void start_tracing(void) {
  DECAF_stop_vm();
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
  keystroke_handle = DECAF_register_callback(DECAF_KEYSTROKE_CB,
    keystroke_callback, &keystroke_enabled);
  /*
   *don't register these for now
  block_end_handle =  DECAF_registerOptimizedBlockEndCallback(
    block_end_callback, NULL, INV_ADDR, INV_ADDR);
  */
  block_begin_handle =  DECAF_registerOptimizedBlockBeginCallback(
    block_begin_callback, NULL, INV_ADDR, INV_ADDR);
  interrupt_handle = DECAF_register_callback(DECAF_INTR_CB,
    interrupt_callback, NULL);
  DECAF_start_vm();
}

static void vmcall_callback(DECAF_Callback_Params* params) {
  DECAF_stop_vm();
  int callnum; 
  if(!params)
    return;
  callnum = params->ie.env->regs[R_EAX];

  DECAF_printf("Got vmcall number %x!\n", callnum);
  /*
  if(callnum == 0) {
    start_tracing();
  } else {
    stop_tracing();
  }
  */
  DECAF_start_vm();
}


void set_filename(Monitor *mon, const QDict *qdict) {
	const char* filename_str = qdict_get_str(qdict, "filepath");
  strncpy(trace_filename, filename_str, 128);
  DECAF_printf("set trace file to %s\n", trace_filename);
}

void enable_use_sysenter(Monitor *mon, const QDict *qdict) {
  use_sysenter = 1;
  DECAF_printf("Using sysenter_eip as an offset\n");
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
{
  .name   = "use_sysenter",
  .args_type  = "",
  .mhandler.info  = enable_use_sysenter,
  .params   = "",
  .help   = "use the sysenter_eip as an address offset"
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
