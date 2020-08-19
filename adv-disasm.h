#ifndef __adv_disasm_h__
#define  __adv_disasm_h__

#include "type-db.h"
#include "common.h"
# pragma pack(push,1)
typedef struct tag_insn_info
{
	INSN_BASIC_INFO basic_info;
	INSN_EXEC_INFO exec_info;
	PGENERAL_TYPE op_type,base_reg_type; // operand type, and structure type
	char src_type_set:1;
	char dst_type_set:1;
	char base_reg_type_set:1;
	char arg:1;
	char var:1;
	union
	{
	short arg_no;//arg
	short disp;// var
	};
	char * comments;
}INSN_INFO,*PINSN_INFO;
# pragma pack(pop)

struct function_disasm_info;
enum enum_bb_type {BB_SEQ,BB_UB,BB_CB,BB_FOR,BB_IF,BB_IFN,BB_IF_ELSE,BB_IFN_ELSE,BB_DO_WHILE,BB_WHILE_DO,BB_GOTO,BB_ALIAS,BB_IF_ELSE_TEMP,BB_IFN_ELSE_TEMP};

typedef struct basic_block 
{
	int bb_type;
	unsigned int flag;   
	unsigned int start,end;
	DLIST insn;
	struct basic_block  *p_bb_follow;
	union
	{
	struct basic_block  *tk_branch; // branch ,NULL if doesn't exist
                      // to tag whether it has been processed or not
                      // branch ,NULL if doesn't exist
	void  *p_ext_data; // compound block, such as if else. 
	struct basic_block  *p_bb_body; // "if {}" 
	};
	int count;                                    
	//struct function_disasm_info * p_func;
	SLIST *stmt_list;
} BASIC_BLOCK,*PBASIC_BLOCK;

typedef struct inline_basic_block 
{
	BASIC_BLOCK common;
	int kind;
	int n_para;
	char  para_reg[1]; // parameters are by register.
} INLINE_BLOCK,*PINLINE_BLOCK;


#define BB_FLAG_PROCESSED 1
#define BB_FLAG_LOOP 2
#define BB_FLAG_EXCLUDE 4
#define BB_FLAG_GOTO 8
#define BB_FLAG_ENDLOOP 0x10
#define BB_FLAG_JUMPTARGET 0x20
#define BB_FLAG_UB    0x40
#define BB_FLAG_RET   0x80
#define BB_FLAG_CB    0x100
#define BB_FLAG_CONT  0x200
#define BB_FLAG_BRK   0x400
//
// extended dara for "if else" "do while " "while do "
//

typedef 	struct tag_for_loop_dat
{
	PBASIC_BLOCK  p_bb_init;
	PBASIC_BLOCK  p_bb_inc;
	PBASIC_BLOCK  p_bb_body;
} FOR_LOOP_DAT,*PFOR_LOOP_DAT;

typedef 	struct tag_if_else_dat
{
	PBASIC_BLOCK p_bb_tk;
	PBASIC_BLOCK p_bb_ntk;
} IF_ELSE_DAT,*PIF_ELSE_DAT;
typedef 	struct tag_while_dat
{
	PBASIC_BLOCK p_bb_body;
	PBASIC_BLOCK p_bb_cond;
} WHILE_DAT,*PWHILE_DAT;




typedef struct function_disasm_info
{
	unsigned char processed:1;
	unsigned char exported:1;
	unsigned char type:1; //ASMPROC  or  C FUNCTION
	unsigned int addr;  // 32bit ip or cs:ip
	short frame_size,para_size;
	SLIST  bb_list;
	SLIST  var_list;
	SLIST  parameter_list;

	char * name;
	PBASIC_BLOCK first_bb,epilog_bb;

	

} FUNC_DISASMINFO,*PFUNC_DISASMINFO;

#define  PROC_TYPE_ASMPROC   0
#define  PROC_TYPE_CFUNCTION 1


typedef struct _propage_task
{
	bool dir_up; // propagate up ward?
	bool processed;
	int type ;// ptopagate comments, type,value?
	void * data;// to be propaged. what it is depends on type

	OPERAND_R_M r_m;
	PBASIC_BLOCK p_bb;
	DLIST * p_node;
	PFUNC_DISASMINFO p_func;// to get bb_list
} PROPAGATE_TASKINFO,*PPROPAGATE_TASKINFO;

int		add_propagate_reg_task(
		PFUNC_DISASMINFO p_func,
		DLIST* p_start,
		PBASIC_BLOCK bb,    // from next insn and downward, if insn the last one in bb, don't worry
		REG_CODE* reg,
		int type,
		void *data,
		bool dir_up);

int		add_propagate_rm_task(
		PFUNC_DISASMINFO p_func,
		DLIST* p_start,
		PBASIC_BLOCK bb,    // from next insn and downward, if insn the last one in bb, don't worry
		OPERAND_R_M* p_r_m,
		int type,
		void *data,
		bool dir_up); 
int add_insn(PBASIC_BLOCK bb,PINSN_BASIC_INFO p_insn_info);

PBASIC_BLOCK add_basic_block(SLIST * p_bb_list,unsigned int start_eip);
PBASIC_BLOCK split_bb(PFUNC_DISASMINFO p_func,PBASIC_BLOCK bb_split,DLIST *q);
SLIST * order_bb(SLIST *bb_list);
PBASIC_BLOCK get_basic_block_by_flag( PFUNC_DISASMINFO func,int flag_to_match);
PBASIC_BLOCK add_basic_block(PFUNC_DISASMINFO func,unsigned int start_eip);
PBASIC_BLOCK lookup_basic_block(PFUNC_DISASMINFO func,unsigned int start_eip);
void reset_basic_block_counter( PFUNC_DISASMINFO func);
void reset_basic_block_flag( PFUNC_DISASMINFO func, unsigned int mask);

typedef enum _disasm_mode {UNKNOWN,BIN16,BIN32,PE32}DISASM_MODE;

extern DISASM_MODE disasm_mode;
__inline bool real_mode() {return disasm_mode==BIN16;}
__inline bool pe32_mode() {return disasm_mode==PE32;}
#endif  //__adv_disasm_h__