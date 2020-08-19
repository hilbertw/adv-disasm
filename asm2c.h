#ifndef __ASM2C_H__
#define __ASM2C_H__
#include "common.h"
#include "type-db.h"

struct _statement;
//
//    value in a register can be:
//               imm, var,par,dat, addr_of, result of function call
//     expr can be: 
//               1)op between register, register/imm
//               2) addr of
//
//      stmt can be: 
//               1) expr
//               2) function call
//

typedef enum _asm2c_data_type {
	ASM2C_REGSTATE_UNKNOWN, // can not be used. not assigned a value yet
	ASM2C_REGSTATE_NONE, // can not be used. not assigned a value yet
	ASM2C_REGSTATE_IMM,
	ASM2C_REGSTATE_SYSREG,
	ASM2C_REGSTATE_MEM,
	ASM2C_REGSTATE_DAT,
	ASM2C_REGSTATE_VAR,
	ASM2C_REGSTATE_PAR,
	ASM2C_REGSTATE_TMP,
	ASM2C_REGSTATE_EXP,
	ASM2C_REGSTATE_HIWORD_EXP,//for imul
	ASM2C_REGSTATE_LOWORD_EXP,//for imul
	ASM2C_REGSTATE_Q_EXP,//for idiv
	ASM2C_REGSTATE_R_EXP,//for idiv
}ASM2C_REGSTATE_TYPE;
//
// define state of a (pseudo) register
//
typedef	struct _asm2c_reg_state
{
	ASM2C_REGSTATE_TYPE type;// expression, mem, imm.
	union 
	{
	unsigned int imm; //  imm
	unsigned int off; // var/par offset
	unsigned int address; // data
	unsigned int pseudo_regno; // load mem 
	REG_CODE reg; // load ctrl reg 
	struct _statement * expression;// arith op
	}u; 
}ASM2C_REGSTATE,*PASM2C_REGSTATE;

typedef enum _asm2c_statement_type {

	ASM2C_STYPE_ADD,
	ASM2C_STYPE_SUB,
	ASM2C_STYPE_MUL,
	ASM2C_STYPE_DIV,
	ASM2C_STYPE_IMUL,
	ASM2C_STYPE_IDIV,
	ASM2C_STYPE_XOR,
	ASM2C_STYPE_OR,
	ASM2C_STYPE_AND,
	ASM2C_STYPE_NOT,
	ASM2C_STYPE_NEG,
	ASM2C_STYPE_SAL,
	ASM2C_STYPE_SAR,
	ASM2C_STYPE_SHL,
	ASM2C_STYPE_SHR,
	ASM2C_STYPE_INC,
	ASM2C_STYPE_DEC,
	ASM2C_STYPE_NONEXP,
	ASM2C_STYPE_CALL,//
	ASM2C_STYPE_ASSIGN,
	
	ASM2C_STYPE_ASM,
	ASM2C_STYPE_JUNCON,
	ASM2C_STYPE_JCON=0x40,
	ASM2C_STYPE_JO=ASM2C_STYPE_JCON ,
	ASM2C_STYPE_JNO	 ,
	ASM2C_STYPE_JB	 ,
	ASM2C_STYPE_JNB	 ,
	ASM2C_STYPE_JE	 ,
	ASM2C_STYPE_JNE	 ,
	ASM2C_STYPE_JNA	 ,
	ASM2C_STYPE_JA   ,
	ASM2C_STYPE_JS	 ,
	ASM2C_STYPE_JNS	 ,
	ASM2C_STYPE_JPE	 ,
	ASM2C_STYPE_JPO	 ,
	ASM2C_STYPE_JL	 ,
	ASM2C_STYPE_JNL	 ,
	ASM2C_STYPE_JNG  ,
	ASM2C_STYPE_JG	 ,
	ASM2C_STYPE_JCON_LIMIT,
	ASM2C_STYPE_IF,
	ASM2C_STYPE_IF_ELSE,
	ASM2C_STYPE_DOWHILE,
	ASM2C_STYPE_WHILEDO,
	ASM2C_STYPE_FOR,
	ASM2C_STYPE_NONE
}ASM2C_STYPE;

typedef struct _statement
{
	ASM2C_STYPE op;
	union
	{
		ASM2C_REGSTATE dst;
		ASM2C_REGSTATE operand[2];// for arith/logic op
		struct {
			SLIST * parameter_list;// for call
			PFUNCTION_INFO  p_func_prototype;
		} call_context;
		struct {
			unsigned int dst_eip;	
			struct _statement * p_cond_expr;
		} jump_context;
	};
	PINSN_INFO p_insn;// for asm

}STATEMENT,*PSTATEMENT;


typedef struct _if_statement
{
	ASM2C_STYPE op;

	SLIST  * if_stmt;
	int n_stmt;
	SLIST  * p_stmt[1]; // stmt needs reschedule to make a condition expression
}IF_STATEMENT,*PIF_STATEMENT;
typedef struct _if_else_statement
{
	ASM2C_STYPE op;

	SLIST  * if_stmt,*else_stmt;
	int n_stmt;
	SLIST  * p_stmt[1]; // stmt needs reschedule to make a condition expression
}IF_ELSE_STATEMENT,*PIF_ELSE_STATEMENT;

//
// each pseudo -register is associated with a mem_info
//
// same as that in MEM_DESC. keep base or index register states, not just a reg no.


typedef	struct _asm2c_mem_info
{
	int pseudo_regno;
	long disp; 
	ASM2C_REGSTATE base,index;//
    
	unsigned char scale:2;
	unsigned char seg:3;
	unsigned char fmt:2; // ADDRESS_FORMAT:no base, no index,direct addressing
	unsigned char stack:1;// stack or not
	unsigned char predefined:1;// the arg or var is added  by user?
	PDECLARATOR decl;

}ASM2C_MINFO,*PASM2C_MINFO;


typedef enum macro_bb_type
{
	MBB_SEQ,MBB_FOR,MBB_IF,MBB_ELSE,MBB_IF_ELSE,MBB_WHILEDO,MBB_DOWHILE,
	MBB_DOWHILE1,MBB_LOOP,MBB_NOSET
} MBB_TYPE;
//
// macro basic block.
//
// if-mbb, if-else-mbb, for-mbb, do-while-mbb, while-mbb
//

typedef struct macro_bb
{
	MBB_TYPE type;
	unsigned int first_eip;
	unsigned int last_eip; // eip of successive mbb
	int n_bb;
	SLIST * sub_mbb_list;
	SLIST * sub_mbb_list_sec;
	PBASIC_BLOCK bb[1];
} MBB,*PMBB;

void asm2c_func (PFUNC_DISASMINFO func);
void asm2c_setenv_for_func (PFUNC_DISASMINFO p_func);
PASM2C_MINFO get_minfo_by_pseudo_regno(int pseudo_regno);

char * asm2c_calloc( size_t size);
SLIST * asm2c_add_node(SLIST * head, size_t extra_size);
SLIST * asm2c_add_node_ex(SLIST_EX * head, size_t extra_size);
void asm2c_bb (PBASIC_BLOCK p_bb,SLIST_EX *p_list);

#endif // __ASM2C_H__


