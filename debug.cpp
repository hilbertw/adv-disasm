#define _CRT_SECURE_NO_WARNINGS 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "ifetcher.h"
#include "adv-disasm.h"
#include "util.h"
#include "asm2c.h"
extern char * segment_name[];
extern char *reg16_name[];
extern char *reg8_name[];

static void dump_reg(REG_CODE &reg)
{

		switch(reg.reg_cat)
		{
			case RC_REGG8: printf("%s,", reg8_name[reg.reg_no]);break;
			case RC_REGG16: printf("%s,", reg16_name[reg.reg_no]);break;
			case RC_REGG32: printf("e%s,", reg16_name[reg.reg_no]);break;
			case RC_REGCR: printf("cr%d,", reg.reg_no);break;
			case RC_REGSEG: printf("%s,", segment_name[reg.reg_no]);break;

		}
}
static void dump_mem(MEM_DESC &mem)
{
    printf("%s:",segment_name[mem.seg]);
	switch(mem.fmt)
		{
	case AT_BASE: printf("[%s%c%x],", reg16_name[mem.base_reg_no],mem.disp>0?'+':'-',
					   mem.disp>0?mem.disp:-mem.disp);break;
	case AT_INDEX: printf("[%s*%d%c%x],", reg16_name[mem.base_reg_no],1<<mem.scale,mem.disp>0?'+':'-',
					   mem.disp>0?mem.disp:-mem.disp);break;
	case AT_FULL:  printf("[e%s+e%s*%d%c%x],", reg16_name[mem.base_reg_no],reg16_name[mem.index_reg_no],1<<mem.scale,mem.disp>0?'+':'-',
					   mem.disp>0?mem.disp:-mem.disp);break;
	case AT_DIRECT: printf("[%x],", mem.disp);break;
		}
}
void dump_rm(OPERAND_R_M* p_r_m)
{
	switch(p_r_m->type)
	{
	case OT_REG:dump_reg(p_r_m->operand_desc.reg);break;
	case OT_MEM:dump_mem(p_r_m->operand_desc.mem);break;
	}
}



void print_insn(PINSN_INFO insn)
{
	char line[200];
	int len;
	len=sprintf(line,"\n%08x ",insn->basic_info.eip);
	len+=disasm_line(line+len,&insn->basic_info);
	line[len++]=0;
	printf("%s",line);
}
void print_bb_insn(PBASIC_BLOCK p_bb)
{
	char line[200];
	int len;
	DLIST *p=p_bb->insn.next;

	while(p!=&(p_bb->insn))
	{

		PINSN_INFO p_insn=(PINSN_INFO)(p+1);

		
		len=sprintf(line,"\n%08x ",p_insn->basic_info.eip);
		len+=disasm_line(line+len,&p_insn->basic_info);
		line[len++]=0;

		printf("%s",line);
		p=p->next;
	}
	printf("\n");
}
void dump_propgate(char *msg,PPROPAGATE_TASKINFO p)
{
	PINSN_INFO p_insn=(PINSN_INFO)(p->p_node+1);

	printf("%s--",msg);
	//print_insn(p_insn);
	dump_rm(&p->r_m);
	printf("%s\n",p->dir_up?"up":"down");


}




void dump_reg_state(PASM2C_REGSTATE p_reg_state);
char *sz_op_sym[]={"+","-","*","/","*","%","^","|","&","!","~",">>","<<",">>","<<","++","--"};

void dump_stmts(SLIST * p);



void dump_stmt(PSTATEMENT p_stmt)
{
	



	
	if(p_stmt->op<=ASM2C_STYPE_DEC) 
	{
		
		dump_reg_state(&p_stmt->operand[0]);
		printf(" %s ",sz_op_sym[p_stmt->op]);
		dump_reg_state(&p_stmt->operand[1]);
	}
	else if(p_stmt->op==ASM2C_STYPE_ASSIGN) 
	{
		dump_reg_state(&p_stmt->operand[0]);
		printf("=");dump_reg_state(&p_stmt->operand[1]);
	}
	else if(p_stmt->op==ASM2C_STYPE_ASM) 
	{
	if(p_stmt->p_insn)print_insn(p_stmt->p_insn);
	}
	else if(p_stmt->op==ASM2C_STYPE_IF) 
	{
	
		PIF_STATEMENT p_if=(PIF_STATEMENT)p_stmt;
		printf("if(){\n");
		dump_stmts(p_if->if_stmt);
		printf("}\n");
	}
}
void dump_minfo(PASM2C_MINFO p_minfo)
{
	if (p_minfo->decl)
	{
		printf("%s",p_minfo->decl->identifier);
	}
	else
	{
	if(p_minfo->stack) printf("stack ");
	printf("%x ",p_minfo->disp);

	if(p_minfo->fmt&AT_BASE)	{printf("base:");dump_reg_state(&p_minfo->base);}
	if(p_minfo->fmt&AT_INDEX){printf("[(");dump_reg_state(&p_minfo->index);	printf(")*%x]",1<<p_minfo->scale);}

	}
}
SLIST  pseudo_reg_list;
PASM2C_MINFO get_minfo_by_pseudo_regno(int pseudo_regno)
{
	SLIST *	p = pseudo_reg_list.next;

	while (p)
	{
		PASM2C_MINFO p_minfo = (PASM2C_MINFO)(p + 1);

		if (p_minfo->pseudo_regno == pseudo_regno) return p_minfo;

		p = p->next;

	}
	return NULL;

}

void dump_reg_state(PASM2C_REGSTATE p_reg_state)
{

	switch(p_reg_state->type)
	{

	case ASM2C_REGSTATE_IMM:printf("I:%x ",p_reg_state->u.imm);break;
	case ASM2C_REGSTATE_MEM:
		dump_minfo(get_minfo_by_pseudo_regno(p_reg_state->u.pseudo_regno));
		break;
	case ASM2C_REGSTATE_HIWORD_EXP:
	case ASM2C_REGSTATE_LOWORD_EXP:
	case ASM2C_REGSTATE_Q_EXP:
	case ASM2C_REGSTATE_R_EXP:
	case ASM2C_REGSTATE_EXP:
		dump_stmt(p_reg_state->u.expression); 
		//printf("expr");
		break;
	case ASM2C_REGSTATE_SYSREG:
		printf("reg %x:%x",p_reg_state->u.reg.reg_cat,p_reg_state->u.reg.reg_no);
		break;
	default:printf("X:%x ",p_reg_state->type);
	
	}
}


void dump_stmts(SLIST * p)
{
	while(p)
	{

		PSTATEMENT p_stmt=(PSTATEMENT)(p+1);


		dump_stmt(p_stmt);
		printf("\n");
		p=p->next;
	}
}

void print_ident(int n_ident)
{
	while(n_ident) {printf("    ");n_ident--;}
}
void dump_mbb(SLIST * p, int n_ident)
{
	PMBB p_mbb;
	for(;p;p=p->next)
	{
		p_mbb=(PMBB)(p+1);
		printf("\n%04x",p_mbb->first_eip); 
		print_ident(n_ident);

		switch(p_mbb->type)
		{
		case MBB_IF: {printf("if {"); }break;
		case MBB_ELSE: {printf("else {"); }break;
		case MBB_FOR: {printf("for {"); }break;
		case MBB_WHILEDO: {printf("while {"); }break;
		case MBB_DOWHILE: {printf("do {"); }break;
		case MBB_SEQ: {printf("..."); } continue;
		case MBB_LOOP: {printf("loop {"); }break;
		}
		dump_mbb(p_mbb->sub_mbb_list,n_ident+1);
		printf("\n%04x",p_mbb->last_eip); 
		print_ident(n_ident);
		printf("}"); 

	}
}

void dump_bb(SLIST * p)
{
	while(p!=NULL)
	{
		PBASIC_BLOCK p_bb=(PBASIC_BLOCK)(p+1);

		printf("%x,%x,%x,%x",p_bb->start,p_bb->end,p_bb->tk_branch,p_bb->p_bb_follow);

		if(NULL!=p_bb->tk_branch)
		{
			printf("-->%x",p_bb->tk_branch->start);
		}
		if(NULL!=p_bb->p_bb_follow)
		{
			printf("+->%x",p_bb->p_bb_follow->start);
		}
		if(p_bb->flag&BB_FLAG_CB) printf("-C");
		if(p_bb->flag&BB_FLAG_UB) printf("-U");
		if(p_bb->flag&BB_FLAG_LOOP) printf("-L");
		printf("\n");

		//print_bb_insn(p_bb);
		p=p->next;
	}
}

void dump_bbs(PBASIC_BLOCK p_bb,int n_ident)
{
	while(p_bb)
	{
		print_ident(n_ident);

		switch(p_bb->bb_type)
		{
		case BB_IF: 
		case BB_IFN: 

			print_bb_insn(p_bb);
			
			print_ident(n_ident);
			printf("if (){\n"); 		
			dump_bbs(p_bb->p_bb_body,n_ident+1);
			
			print_ident(n_ident);
			printf("}\n");	
			break;
		case BB_IF_ELSE: 

			print_bb_insn(p_bb);
			
			print_ident(n_ident);
			printf("if (){\n"); 
			dump_bbs(((PIF_ELSE_DAT)p_bb->p_ext_data)->p_bb_ntk,n_ident+1);
			
			print_ident(n_ident);
			printf("\n} else {\n"); 
			//print_bb_insn(p_bb);
			dump_bbs(((PIF_ELSE_DAT)p_bb->p_ext_data)->p_bb_tk,n_ident+1);
			
			print_ident(n_ident);
			printf("}\n");	
			break;
		case BB_FOR: 
			printf("for "); 
			break;
		case BB_WHILE_DO:
			print_bb_insn(p_bb);
			print_ident(n_ident);
			printf("while (){\n"); 
			dump_bbs(((PWHILE_DAT)p_bb->p_ext_data)->p_bb_body,n_ident+1);
			print_ident(n_ident);
			printf("}\n"); 
			 break;
		case BB_DO_WHILE: 
			//print_bb_insn(p_bb);
			print_ident(n_ident);
			printf("do {\n"); 
			dump_bbs(((PWHILE_DAT)p_bb->p_ext_data)->p_bb_body,n_ident+1);

			print_bb_insn(p_bb);
			print_ident(n_ident);
		    printf("} while ()\n");
			break;
		case BB_SEQ: 
		default:
			print_ident(n_ident);
			//printf("{"); 
		//case BB_LOOP:
		//	printf("loop {"); 
			print_bb_insn(p_bb);

			print_ident(n_ident);
			//printf("}\n");	
			 break;
		}
		if(p_bb==p_bb->p_bb_follow)
		{
			break;
		}

		p_bb=p_bb->p_bb_follow;

	}
}