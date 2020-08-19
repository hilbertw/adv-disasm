#define   _CRT_SECURE_NO_DEPRECATE 1
#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string.h>
#include <instr_db.h>
#include <common.h>
#include "adv-disasm.h"
#include "guidinfo.h"
//
// map reg number in guidinfo_rg_no to corresponding reg category
//
char map_reg_cat(int reg_no)
{
	char c;
	if(reg_no<8) c=RC_REGG8;
	else if(reg_no>=24) c=RC_REGSEG;
	else if(reg_no>=16) c=RC_REGG32;
	else c=RC_REGG16;
	return c;
}
char map_reg_no(int reg_no)
{
	char c;
	if(reg_no<8) c=reg_no;
	else if(reg_no>=24) c=reg_no-24;
	else if(reg_no>=16) c=reg_no-16;
	else c=reg_no-8;
	return c;
}

//
//in a caller
// propagating a called asm proc incoming register comments  in caller: bottom up  till the register is written 
//
void do_reg_propagate_in_caller(DLIST *pnode,DLIST *p_end_node, int reg_no, char *comments)
{
	REG_CODE reg_code;
	reg_code.reg_cat=map_reg_cat(reg_no);
	reg_code.reg_no=map_reg_no(reg_no);
	//
	// 
	//

	while(pnode!=p_end_node)
	{
		PINSN_INFO insn=(PINSN_INFO)(pnode+1);
	//printf("match para:%x-%s-%x-%x-%x\n",insn->basic_info.eip,comments,reg_no,*(char *)&reg_code,*(char *)&insn->exec_info.reg);
		// stops at a writ to the said register
		if(reg_equ(insn->exec_info.reg,reg_code))
		{
			if(insn->exec_info.flag&1) {
				insn->comments=comments;
				//printf("set para:%x-%s\n",insn->basic_info.eip,comments);
				break;
			}
		}
		else if(insn->exec_info.r_m.type=OT_REG&&reg_equ(insn->exec_info.r_m.operand_desc.reg,reg_code))
		{
			if(!(insn->exec_info.flag&1)) {	
				insn->comments=comments; 
				//printf("set para:%x-%s\n",insn->basic_info.eip,comments);
				break;
			}
		}

		pnode=pnode->prev;
	}
}

void reg_propagate_in_caller(PBASIC_BLOCK bb)
{
	DLIST *pnode=bb->insn.prev;
	DLIST *p_end_node=&bb->insn;
	for(;pnode!=p_end_node;pnode=pnode->prev)
	{
		PINSN_INFO insn=(PINSN_INFO)(pnode+1);
		//
		// insn is a call?
		//
		if(insn->basic_info.p_instr_desc->index!=callr) continue;
		PPROCEDURE_REC proc_rec=lookup_proc( insn->exec_info.imm);
		if(!proc_rec|| proc_rec->type!=PROC_TYPE_ASMPROC) continue; // no proc record or type is not asm proc, skip
		//
		// for each known para of this do insn
		//
		SLIST *p=proc_rec->parameter_list.next;
		while(p)
		{
			PPARAMETER_REC para_rec=(PPARAMETER_REC)(p+1);

			do_reg_propagate_in_caller(pnode->prev,p_end_node,para_rec->reg_no,para_rec->text);

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



void asm_analyze(PFUNC_DISASMINFO func)
{
	//
	// for all bb, analyze
	//
	SLIST * p=func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		reg_propagate_in_caller( bb);

		p=p->next;
	}
}
