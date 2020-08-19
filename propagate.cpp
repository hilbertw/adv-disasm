#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "common.h"
#include "adv-disasm.h"
#include "guidinfo.h"

SLIST  propagate_task_list;
MEM_POOL mp_analyze;

void dump_propgate(char *msg,PPROPAGATE_TASKINFO p);
void print_insn(PINSN_INFO insn);
//
//
//
static char * for_make_a_type;

PALIAS_TYPE make_a_type(DECLARATOR* p_decl)
{
	PALIAS_TYPE type=(PALIAS_TYPE)mp_calloc(&mp_analyze,sizeof(ALIAS_TYPE));

	if(type)
	{
		type->num_elements=p_decl->num_elements;
		type->pointer_level=p_decl->pointer_level;
		type->type_info=p_decl->type_info;
		type->hdr.type_code=T_TYPEDEF;
		type->hdr.identifier=for_make_a_type;
		type->hdr.size=p_decl->pointer_level?4:p_decl->num_elements*p_decl->type_info->size;
	}
	return type;
}
//
//
//

int		add_propagate_reg_task(
		PFUNC_DISASMINFO p_func,
		DLIST* p_start,
		PBASIC_BLOCK bb,    // from next insn and downward, if insn the last one in bb, don't worry
		REG_CODE* reg,
		int type,
		void *data,
		bool dir_up) // not up ward
{
	SLIST * p=mp_add_node(&propagate_task_list,sizeof(PROPAGATE_TASKINFO),&mp_analyze);
	if(!p) return 0;

	PPROPAGATE_TASKINFO p_task=(PPROPAGATE_TASKINFO)(p+1);
	
	p_task->p_func=p_func;
	p_task->type=type;
	p_task->data=data;
	p_task->p_node=p_start;
	p_task->p_bb=bb;
	p_task->dir_up=dir_up;
	p_task->r_m.type=OT_REG;
	p_task->r_m.operand_desc.reg=*reg;

	dump_propgate("add:",p_task);
	return 1;
}

int		add_propagate_rm_task(
		PFUNC_DISASMINFO p_func,
		DLIST* p_start,
		PBASIC_BLOCK bb,    // from next insn and downward, if insn the last one in bb, don't worry
		OPERAND_R_M* p_r_m,
		int type,
		void *data,
		bool dir_up) // not up ward
{
	SLIST * p=mp_add_node(&propagate_task_list,sizeof(PROPAGATE_TASKINFO),&mp_analyze);
	if(!p) return 0;

	PPROPAGATE_TASKINFO p_task=(PPROPAGATE_TASKINFO)(p+1);

	p_task->p_func=p_func;
	p_task->type=type;
	p_task->data=data;
	p_task->p_node=p_start;
	p_task->p_bb=bb;
	p_task->dir_up=dir_up;
	p_task->r_m=*p_r_m;
	dump_propgate("add:",p_task);
	return 1;
}
__inline bool match_r_r_m_i(REG_CODE reg,OPERAND_R_M* p_r_m)
{
	return (p_r_m->type==OT_REG &&
			reg_equ(p_r_m->operand_desc.reg,reg));

}
__inline bool match_mem(OPERAND_R_M* p_r_m0,OPERAND_R_M* p_r_m1)
{
		switch(p_r_m0->operand_desc.mem.fmt)
		{
		case AT_BASE:
			if(p_r_m0->operand_desc.mem.base_reg_no!=p_r_m1->operand_desc.mem.base_reg_no) break;
			goto l1;

		case  AT_FULL:
			if(p_r_m0->operand_desc.mem.base_reg_no!=p_r_m1->operand_desc.mem.base_reg_no) break;

		case AT_INDEX:
			if(p_r_m0->operand_desc.mem.scale!=p_r_m1->operand_desc.mem.scale
			||p_r_m0->operand_desc.mem.index_reg_no!=p_r_m1->operand_desc.mem.index_reg_no) break;

		case AT_DIRECT:
l1:
			return (p_r_m1->operand_desc.mem.fmt==p_r_m0->operand_desc.mem.fmt
				&&p_r_m0->operand_desc.mem.disp==p_r_m1->operand_desc.mem.disp);
		}
		return false;
}
	

//
// we only match reg and mem
//
void dump_rm(OPERAND_R_M* p_r_m);
__inline bool match_r_m_i(OPERAND_R_M* p_r_m0,OPERAND_R_M* p_r_m1)
{
	//dump_rm(p_r_m0);
	//dump_rm(p_r_m1);
	switch(p_r_m0->type)
	{
	case OT_REG:
		return (p_r_m1->type==OT_REG &&reg_equ(p_r_m0->operand_desc.reg,p_r_m1->operand_desc.reg));

	case OT_MEM:
		return p_r_m1->type==OT_MEM&&match_mem(p_r_m0,p_r_m1);

	default:
		break;
	}
	return false;
}
__inline bool match_base_reg(OPERAND_R_M* p_rm_to_check,OPERAND_R_M* p_rm_in_propagate,char addr_size)
{
	//
	// p_rm_in_propagate is a register?
	//
	// p_rm_to_check if base+disp?
	return p_rm_in_propagate->type==OT_REG
		&&p_rm_in_propagate->operand_desc.reg.reg_cat==((addr_size==32)?RC_REGG32:RC_REGG16)
		&& p_rm_to_check->type==OT_MEM
		&& p_rm_to_check->operand_desc.mem.fmt==AT_BASE
		&& p_rm_to_check->operand_desc.mem.base_reg_no==p_rm_in_propagate->operand_desc.reg.reg_no;
}

//
// only deal with mov. betwwen reg and rm. imm does not make sense here.
// propagate a r/m's information till it is writeen again. so recursive  stops when the register is the dst.
//
typedef enum _propagate_action_ {REG_UP,REG_DOWN,RM_UP,RM_DOWN,NO_ACTION}PROPAGATE_ACTION;

//void do_propagate_downward(PBASIC_BLOCK bb,DLIST * p_node,OPERAND_R_M* p_r_m, int type, void * data, int loop_count)



void do_propagate_downward(PPROPAGATE_TASKINFO p_task_info,PBASIC_BLOCK bb,DLIST * p_node)
{
	//PBASIC_BLOCK bb=p_task_info->p_bb;
	//DLIST * p_node=p_task_info->p_node;
	OPERAND_R_M* p_r_m=&p_task_info->r_m;
	int type=p_task_info->type;
	void * data=p_task_info->data;

	bb->flag|=BB_FLAG_PROCESSED;
	//if(bb->count) return; // loop found
	//bb->count++;
	//
	//for all instruction in bb. check base register, and disp of mem operand if there is
	//
	DLIST * q;//bb->insn.next;
	for(q=p_node;q!=&bb->insn;q=q->next)
	{
		PINSN_INFO p_insn=(PINSN_INFO)(q+1);
		PROPAGATE_ACTION action;
		bool stop_recursion=false;


		//printf("%x--%x:%d:%d:%d\n",p_insn->basic_info.eip, p_insn->exec_info.r_m.type,
		//	p_insn->exec_info.r_m.operand_desc.mem.fmt,
		//	p_insn->exec_info.r_m.operand_desc.mem.base_reg_no,
		//	p_insn->exec_info.r_m.operand_desc.mem.disp);
		//print_insn(p_insn);

		//
		// just match mov.if the src matches, add ,dst to propagating task list.if matches dst, recursion ends.
		// those insn's without direction flag, are with  imm , no need to propagate
		//
		if(p_insn->basic_info.p_instr_desc->index==mov&&p_insn->basic_info.p_instr_desc->dir_mask)
		{
			//
			// flag==1, r,r/m
			// flag==0 , r/m,r
			if(match_r_m_i(&p_insn->exec_info.r_m,p_r_m))
			{
				if(p_insn->exec_info.flag&EXEC_F_DIR)
				{
					// dst's type found, propagate downwards
					action=REG_DOWN;
				}
				else
				{
					// register is being writeen/changing type  here. stop recursion, don't type set
					action=NO_ACTION;
					//stop_recursion=true;
				}
			}
			else   if(match_r_r_m_i(p_insn->exec_info.reg,p_r_m))
			{
				if(!(p_insn->exec_info.flag&EXEC_F_DIR))
				{
					// dst's type found, propagate downwards
					action=RM_DOWN;
				}
				else
				{
					// register is being writeen/changing type  here. stop recursion, don't type set
					action=NO_ACTION;
					//stop_recursion=true;
				}
			}
			else if(match_base_reg(&p_insn->exec_info.r_m,p_r_m,p_insn->basic_info.addr_size))
			{
				PMEMBERINFO p_member;

				PGENERAL_TYPE base_type= get_base_type((PGENERAL_TYPE)data);
				if(base_type->type_code==T_STRUCT
					&&NULL!=(p_member=get_struct_field(base_type,p_insn->exec_info.r_m.operand_desc.mem.disp)))
				{
					data=make_a_type(&p_member->decl);
					action=REG_DOWN;
				}
				else
					continue;
			}
			else
				continue;  // mov, no operands matches, go to next insn
		}// xchg only between registers. if matchs any, recursion ends
		else if(p_insn->basic_info.p_instr_desc->index==xchg&&p_r_m->type==OT_REG)
		{
			if(match_r_m_i(&p_insn->exec_info.r_m,p_r_m))
			{
				action=REG_DOWN;
				stop_recursion=true;
			}
			else   if(match_r_r_m_i(p_insn->exec_info.reg,p_r_m))
			{
				action=RM_DOWN;
				stop_recursion=true;
			}
			else continue;// xchg, no operands matches, go to next insn
		}
		else continue;  // not mov and xchg, go to next insn

		switch( action)
		{
		case REG_UP:
				add_propagate_reg_task(
				p_task_info->p_func,
				q->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.reg,
				type,
				data,
				true); // not up ward
				break;
		case REG_DOWN:
				add_propagate_reg_task(
				p_task_info->p_func,
				q->next,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.reg,
				type,
				data,
				false); // not up ward
				break;
		case RM_UP:
				add_propagate_rm_task(
				p_task_info->p_func,
				q->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.r_m,
				type,
				data,
				true);      //  up ward 
				break;
		case  RM_DOWN:
				add_propagate_rm_task(
				p_task_info->p_func,
				q->next,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.r_m,
				type,
				data,
				false); // not up ward 
				break;

		default:  // r/rm is set a new value here. no action, don't set type recursion stops.
			return;

		}

		// insn is a  match,  set type, comments,.../etc
		if(NULL!=p_insn->op_type) 
		{
			// type is already learnt. are them the same?
			return;
		}
		p_insn->op_type=(PGENERAL_TYPE)data;

		if(stop_recursion)return;
		
	}
	//
	// recursive to sucessive bb
	//
	PBASIC_BLOCK bb_next=bb->p_bb_follow;
	
	if(bb_next&&bb_next->start>bb->end)  // branch back is a loop. recursion ends
	{
		p_node=bb_next->insn.next;
		//do_propagate_downward(bb_next,p_node,p_r_m,type,data, loop_count );
			do_propagate_downward(p_task_info,bb_next,p_node);
	}

	bb_next=bb->tk_branch;
	
	if(bb_next&&bb_next->start>bb->end)  // branch back is a loop. recursion ends
	{
		p_node=bb_next->insn.next;
		//do_propagate_downward(bb_next,p_node,p_r_m,type,data, loop_count );
			do_propagate_downward(p_task_info,bb_next,p_node);
	}
}

//
// why up ward? when  a register(src) is moved to a r/m(dst), whose type is known, then the register has the same type.
// a task will be added to do the propagating.
//
// the type should be propagated till the mov where it gets the value.
//
// only deal with mov. betwwen reg and rm. imm does not make sense here.
// propagate a r/m's information till  where it is writeen . so recursive  stops when the register is the dst.
//

//void do_propagate_upward(PBASIC_BLOCK bb,DLIST * p_node,OPERAND_R_M* p_r_m, int type, void * data, int loop_count)
void do_propagate_upward(PPROPAGATE_TASKINFO p_task_info,PBASIC_BLOCK bb,DLIST * p_node)
{

	//PBASIC_BLOCK bb=p_task_info->p_bb;
	//DLIST * p_node=p_task_info->p_node;
	OPERAND_R_M* p_r_m=&p_task_info->r_m;
	int type=p_task_info->type;
	void * data=p_task_info->data;

	bb->flag|=BB_FLAG_PROCESSED;
	//if(bb->count) return; // loop found
	//bb->count++;
	//
	//for all instruction in bb. check base register, and disp of mem operand if there is
	//
	DLIST * q;//bb->insn.next;
	for(q=p_node;q!=&bb->insn;q=q->prev)
	{
		PINSN_INFO p_insn=(PINSN_INFO)(q+1);
		PROPAGATE_ACTION action;
		bool stop_recursion=false;


		//printf("%x--%x:%d:%d:%d\n",p_insn->basic_info.eip, p_insn->exec_info.r_m.type,
		//	p_insn->exec_info.r_m.operand_desc.mem.fmt,
		//	p_insn->exec_info.r_m.operand_desc.mem.base_reg_no,
		//	p_insn->exec_info.r_m.operand_desc.mem.disp);
		//print_insn(p_insn);

		//
		// just match mov.if the src matches, add ,dst to propagating task list.if matches dst, recursion ends.
		// those insn's without direction flag, are with  imm , no need to propagate
		//
		if(p_insn->basic_info.p_instr_desc->index==mov&&p_insn->basic_info.p_instr_desc->dir_mask)
		{
			//
			// flag==1, r,r/m
			// flag==0 , r/m,r
			if(match_r_m_i(&p_insn->exec_info.r_m,p_r_m))
			{
				if(p_insn->exec_info.flag&EXEC_F_DIR)
				{
					// dst's type found, propagate downwards
					action=REG_DOWN;
	
				}
				else
				{
					//src's type found, propagate downwards
					action=REG_UP;
					stop_recursion=true;
				}
			}
			else   if(match_r_r_m_i(p_insn->exec_info.reg,p_r_m))
			{
				if(!(p_insn->exec_info.flag&EXEC_F_DIR))
				{
					// dst's type found, propagate downwards
					action=RM_DOWN;
				}
				else
				{
					// src's type found.register is getting the type  here. stop recursion
					action=RM_UP;
					stop_recursion=true;
				}
			}
			else 
				continue;  // mov, no operands matches, go to next insn
		}// xchg only between registers. if matchs any, recursion ends
		else if(p_insn->basic_info.p_instr_desc->index==xchg&&p_r_m->type==OT_REG)
		{
			if(match_r_m_i(&p_insn->exec_info.r_m,p_r_m))
			{
				action=REG_DOWN;
				stop_recursion=true;
			}
			else   if(match_r_r_m_i(p_insn->exec_info.reg,p_r_m))
			{
				action=RM_DOWN;
				stop_recursion=true;
			}
			else continue;// xchg, no operands matches, go to next insn
		}
		else continue;  // not mov and xchg, go to next insn

		switch( action)
		{
		case REG_UP:
				add_propagate_reg_task(
				p_task_info->p_func,
				q->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.reg,
				type,
				data,
				true);      //  up ward
				break;
		case REG_DOWN:
			add_propagate_reg_task(
				p_task_info->p_func,
				q->next,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.reg,
				type,
				data,
				false);     // not up ward
				break;
		case RM_UP:
				add_propagate_rm_task(
				p_task_info->p_func,
				q->prev,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.r_m,
				type,
				data,
				true);      //  up ward 
				break;
		case  RM_DOWN:
				add_propagate_rm_task(
				p_task_info->p_func,
				q->next,    // from next insn and downward, if insn the last one in bb, don't worry
				bb,         // this bb
				&p_insn->exec_info.r_m,
				type,
				data,
				false);      // not up ward 
				break;

		}

		// insn is a  match,  set type, comments,.../etc
		if(NULL!=p_insn->op_type) 
		{
			// type is already learnt. are them the same?
			return;
		}
		p_insn->op_type=(PGENERAL_TYPE)data;

		if(stop_recursion)return;
		
	}
	//
	// recursive to preceding bb-s, for all bb whose left or right is bb
	//
	SLIST* bb_list=p_task_info->p_func->bb_list.next;
	while(bb_list)
	{
		PBASIC_BLOCK bb_prev=(PBASIC_BLOCK)(bb_list+1);
		if((bb_prev->flag&BB_FLAG_PROCESSED)==0
			&&(bb_prev->p_bb_follow==bb||bb_prev->tk_branch==bb))
		{
			p_node=bb_prev->insn.prev;
			//do_propagate_upward(bb_prev,p_node,p_r_m,type,data, loop_count );
			do_propagate_upward(p_task_info,bb_prev ,p_node);
		}

		bb_list=bb_list->next;
	}


}


void propagate_type()
{
	PPROPAGATE_TASKINFO p_task_info;

	int n_task_ran;
	
	do
	{
		n_task_ran=0;
		SLIST *p=propagate_task_list.next;
		while(p)
		{
			p_task_info=(PPROPAGATE_TASKINFO)(p+1);
			if(!p_task_info->processed)
			{

				//dump_propgate("run",p_task_info);
				reset_basic_block_flag(p_task_info->p_func,BB_FLAG_PROCESSED);
			if(p_task_info->dir_up)
			do_propagate_upward(p_task_info,p_task_info->p_bb,p_task_info->p_node);//,&p_task_info->r_m,p_task_info->type,p_task_info->data,0);
			else
			do_propagate_downward(p_task_info,p_task_info->p_bb,p_task_info->p_node);//,&p_task_info->r_m,p_task_info->type,p_task_info->data,0);

			p_task_info->processed=true;
			n_task_ran++;
			}
			p=p->next;
		}

	}while(n_task_ran);
}
