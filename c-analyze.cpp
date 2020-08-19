#define   _CRT_SECURE_NO_DEPRECATE 1
#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string.h>
#include <instr_db.h>
#include <assert.h>
#include <common.h>
#include "adv-disasm.h"
#include "guidinfo.h"

char map_reg_cat(int reg_no);
char map_reg_no(int reg_no);
bool reg_equ( REG_CODE reg_code1,REG_CODE reg_code2);
char * pe32_lookup_exported_func(unsigned long  address);
char * pe32_check_imported_function_call(unsigned char *code);
PALIAS_TYPE make_a_type(DECLARATOR* p_decl);

SLIST *  get_function_para_list(unsigned int addr)
{
	//
	// 1. look for type information
	//
	char * func_name;
	PFUNCTION_INFO  func_prototype;
	
	//
	// if pe32, is it an exported api?
	//
	if(pe32_mode()) 
		func_name= pe32_lookup_exported_func(addr);

	if(!func_name)
	{
		PPROCEDURE_REC proc_rec=lookup_proc(addr);
		if(proc_rec)
			func_name=proc_rec->name;
	}

	if(func_name)
	func_prototype=lookup_function(func_name);
	else
		func_prototype=NULL;
	
	//
	// a function proto type is known?
	//
	return func_prototype?func_prototype->parameter_list.next:NULL;
}
//
// detecting pe32 imported function calling
//
SLIST *  get_imported_function_para_list(unsigned char *code)
{
	char * func_name;
	PFUNCTION_INFO  func_prototype;
	
	if(!pe32_mode())  return NULL;

	func_name= pe32_check_imported_function_call(code);

	if(func_name)
	func_prototype=lookup_function(func_name);
	else 
		func_prototype=NULL;
	
	//
	// a function proto type is known?
	//
	return func_prototype?func_prototype->parameter_list.next:NULL;
}
//
//in a caller
// propagating a called asm proc incoming register comments  in caller: bottom up  till the register is written 
//
DLIST * do_function_para_type_propagate_in_caller(
	PFUNC_DISASMINFO p_func,
	PBASIC_BLOCK bb,DLIST *qnode,
	PPARAMETERINFO para)
{

	//
	// 
	//

	while(qnode!=&bb->insn)
	{
		PINSN_INFO p_insn=(PINSN_INFO)(qnode+1);

		// found a push, propagate the operand upwards. put downwards
		if(p_insn->basic_info.p_instr_desc->index==push)
		{
			if(p_insn->exec_info.reg.reg_cat!=RC_NOTHING)

				add_propagate_reg_task(
				p_func,
				qnode->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.reg,
				0,
				(void*)make_a_type(&para->decl),
				true); //  up ward
			else 		
				if(p_insn->exec_info.r_m.type!=OT_NONE)

				add_propagate_rm_task(
				p_func,
				qnode->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.r_m,
				0,
				(void*)make_a_type(&para->decl),
				true); //  up ward

			break; // a match
		}
		qnode=qnode->prev;
	}
	return qnode; // return the stop node so that next search can continue from there
}

void propagate_c_function_para_type_in_caller(PFUNC_DISASMINFO p_func,PBASIC_BLOCK bb)
{
	DLIST *pnode=bb->insn.prev;
	for(;pnode!=&bb->insn;pnode=pnode->prev)
	{
		PINSN_INFO insn=(PINSN_INFO)(pnode+1);
		SLIST *p=NULL;
		//
		// insn is a call?, call relative, call an imported func?
		//
		if(insn->basic_info.p_instr_desc->index==callr)
			p=get_function_para_list( insn->exec_info.imm);
		else if(insn->basic_info.p_instr_desc->index==call)
			p=get_imported_function_para_list( insn->basic_info.code+insn->basic_info.prefix_bytes);
		//
		// for each known para of this do insn, start from qnode, to search push, 
		//
		DLIST * qnode=pnode->prev;
		while(p&&qnode!=&bb->insn)
		{
			PPARAMETERINFO para=(PPARAMETERINFO)(p+1);

			// search push upwards. return the node where the search stops. and next para searching  start from there
			qnode=do_function_para_type_propagate_in_caller(p_func,bb,qnode,para);

			p=p->next;
		}
	}
}


//
//  c function  arguments type propagating in caller : bottom up till all push-s are found, only in one bb. calling a function cross bb-s are rear.
//

//
//  in c function  propagates garguments type   : top down  till all insn  in all bb are scanned
//





//
// find_frame_size in first bb.  frame setup code acrossing bb is rear.
//
// sequence 1: 55 8b ec 81 ec c0 00 00 00 
//  push bp, 
//  mov bp,sp 
//  sub sp, size
// 
// sequence 2: enter size, n
//
// return -1: failed.
//        n>0: frame size is n
void find_frame_size( PFUNC_DISASMINFO func)
{
	//
	//for exported func, a jmpwill be seen, skip the jump
	//
	DLIST* p=func->first_bb->insn.next;

	if( ((PINSN_INFO)(p+1))->basic_info.p_instr_desc->index==jmpr)
	{

	}
	unsigned char * code=((PINSN_INFO)(p+1))->basic_info.code; // first insn
	int data_size=((PINSN_INFO)(p+1))->basic_info.data_size;

	p=func->first_bb->insn.prev;            // last insn to calc bb size.
	int code_size=  func->first_bb->end-
					func->first_bb->start+((PINSN_INFO)p)->basic_info.len;

	char code_seq1[]={0x55,0x8b,0xec,0x81,0xec};

	// a health frame, following code_seq1, the rest of insn sub esp, xx, mov esp,ebp,pop ebp,ret
	// totalling 6 bytes
	if (code_size>(sizeof code_seq1)+6&& memcmp(code,code_seq1,sizeof code_seq1)==0)
	{
		 func->frame_size=(data_size==32)?(*(int*)(code+sizeof code_seq1)):(*(short*)(code+sizeof code_seq1));
	}
	// enter xx,xx, leave,ret 5 bytes 
	else if(code_size>5&&code[0]==0xc8)
	{
		func->frame_size=(*(short*)(code+1));
	}
}
//
//resolve_parameter
//
//
// get type info for [ebp+offset]
//
int resolve_parameter( int offset,SLIST * parameter_list,PPARAMETERINFO* ret_parameter)
{
	SLIST *&p=parameter_list;

	int i=0;
	while(p)
	{
		PPARAMETERINFO parameter=(PPARAMETERINFO)(p+1);

		//printf("par byte off:%x,%x\n",parameter->byte_offset,offset);
		if(parameter->byte_offset==offset) {*ret_parameter=parameter;return i;}


		i++;
		p=p->next;
	}
	return -1;
}
//
//resolve_parameter
//
//
// get type info for [ebp+offset]
//
PVAR_REC  resolve_var( int offset,SLIST * var_list)
{
	SLIST * p=var_list;
	while(p)
	{
		PVAR_REC p_var=(PVAR_REC)(p+1);

		printf("var byte off:%x,%x\n",p_var->byte_offset,offset);
		if(p_var->byte_offset==-offset) return p_var;

		p=p->next;
	}
	return NULL;
}

//
// look for retn instructions,must be the last insn of the bb
//
void find_para_size(PFUNC_DISASMINFO func)
{
	SLIST * p=func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);
		DLIST * q=bb->insn.prev;
		PINSN_INFO insn=(PINSN_INFO)(q+1);
		if(insn->basic_info.p_instr_desc->index==retn
			||insn->basic_info.p_instr_desc->index==retfn)
		{
			func->para_size=(short)insn->exec_info.imm;
			return;
		}
		p=p->next;
	}
}

void do_propagate_parameter_name(PBASIC_BLOCK bb,SLIST * parameter_list)
{
	//if(bb->count) return; // loop found
	//bb->count++;
	//
	//for all instruction in bb. check base register, and disp of mem operand if there is
	//
	DLIST * q=bb->insn.next;
	while(q!=&bb->insn)
	{
		PINSN_INFO insn=(PINSN_INFO)(q+1);

		//
		// 
		//
		//printf("%x--%x:%d:%d:%x\n",insn->basic_info.eip, insn->exec_info.r_m.type,
		//	insn->exec_info.r_m.operand_desc.mem.fmt,
		//	insn->exec_info.r_m.operand_desc.mem.base_reg_no,
		//	insn->exec_info.r_m.operand_desc.mem.disp);

		if(insn->exec_info.r_m.type==OT_MEM
			&& insn->exec_info.r_m.operand_desc.mem.fmt==AT_BASE
			&& insn->exec_info.r_m.operand_desc.mem.base_reg_no==5
			&&insn->exec_info.r_m.operand_desc.mem.disp>0)
		{
			PPARAMETERINFO para;

			int para_no=resolve_parameter(insn->exec_info.r_m.operand_desc.mem.disp,
				parameter_list,&para);

			if(-1!=para_no) 
			{
				insn->arg=1;
				insn->op_type=para->decl.type_info;

				//if(insn->exec_info.flag&2) 
				insn->arg_no=para_no;
				insn->comments=para->decl.identifier;
			}
		}
		q=q->next;
	}
	//
	// recursive to sucessive bb
	//
	if(bb->p_bb_follow&&bb->p_bb_follow->start>bb->end)  // branch back is a loop. recursion ends
		do_propagate_parameter_name((PBASIC_BLOCK)(bb->p_bb_follow),parameter_list);
	if(bb->tk_branch&&bb->tk_branch->start>bb->end)  // branch back is a loop. recursion ends
		do_propagate_parameter_name((PBASIC_BLOCK)(bb->tk_branch),parameter_list);
}



void do_propagate_var_name(PBASIC_BLOCK bb,SLIST * var_list)
{
	//if(bb->count) return; // loop found
	//bb->count++;
	//
	//for all instruction in bb. check base register, and disp of mem operand if there is
	//
	DLIST * q=bb->insn.next;
	while(q!=&bb->insn)
	{
		PINSN_INFO insn=(PINSN_INFO)(q+1);
		void dump_rm(OPERAND_R_M* p_r_m);

		//
		// 
		//
		dump_rm(&insn->exec_info.r_m);

		if(insn->exec_info.r_m.type==OT_MEM
			&& insn->exec_info.r_m.operand_desc.mem.fmt==AT_BASE
			&& insn->exec_info.r_m.operand_desc.mem.base_reg_no==5//ebp
			&&insn->exec_info.r_m.operand_desc.mem.disp<0)
		{
			PVAR_REC p_var=resolve_var(insn->exec_info.r_m.operand_desc.mem.disp,
				var_list);

			if(NULL!=p_var) 
			{
				insn->var=1;
				insn->op_type=p_var->decl.type_info;

				//if(insn->exec_info.flag&2) 
				insn->disp=(short)insn->exec_info.r_m.operand_desc.mem.disp;
				insn->comments=p_var->decl.identifier;
			}
		}
		q=q->next;
	}
	//
	// recursive to sucessive bb
	//
	if(bb->p_bb_follow&&bb->p_bb_follow->start>bb->end)  // branch back is a loop. recursion ends
		do_propagate_var_name((PBASIC_BLOCK)(bb->p_bb_follow),var_list);
	if(bb->tk_branch&&bb->tk_branch->start>bb->end)  // branch back is a loop. recursion ends
		do_propagate_var_name((PBASIC_BLOCK)(bb->tk_branch),var_list);
}

void propagate_parameter_type(PFUNC_DISASMINFO p_func)
{
	assert(p_func->type==	PROC_TYPE_CFUNCTION);

	if(!p_func->parameter_list.next) return;

	//do_propagate_parameter_type(func->first_bb,func->parameter_list);
	//

	// for each parameter, add a propagte task
	//

	OPERAND_R_M r_m;
	int disp=8;
	r_m.type=OT_MEM;
	r_m.operand_desc.mem.fmt=AT_BASE;
	r_m.operand_desc.mem.base_reg_no=5;// BP

	SLIST * p=p_func->parameter_list.next;
	while(p)
	{
	    DLIST * p_start=p_func->first_bb->insn.next;
		PPARAMETERINFO parameter=(PPARAMETERINFO)(p+1);

		r_m.operand_desc.mem.disp= disp;

		add_propagate_rm_task(
			p_func,
		p_start,    // from next insn and downward, if insn the last one in bb, don't worry
		p_func->first_bb,         // this bb
		&r_m,
		0,
		parameter->decl.type_info,
		false); // not up ward

		p=p->next;
		disp+=4;
	}
}

void propagate_type();
void reset_basic_block_counter( PFUNC_DISASMINFO p_func);

void c_analyze(PFUNC_DISASMINFO p_func)
{
	//if(!func->exported)
	//find_para_size( func);

	//find_frame_size( func);

	//propagate_parameter_type(func);
	if(p_func->parameter_list.next)
	{
		do_propagate_parameter_name(p_func->first_bb,p_func->parameter_list.next);
		reset_basic_block_counter(p_func);
	}
	if(p_func->var_list.next)
	{
		do_propagate_var_name(p_func->first_bb,p_func->var_list.next);
		reset_basic_block_counter(p_func);
	}
	//
	// for all bb, get type information from called functions, 
	//
	SLIST * p=p_func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		propagate_c_function_para_type_in_caller( p_func,bb);
		p=p->next;
	}
	//
	// propagate function para types
	//
	propagate_type();

}