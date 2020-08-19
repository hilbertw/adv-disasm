
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "ifetcher.h"
#include "adv-disasm.h"
#include "util.h"

//
// opened in disasm_bin.cpp
//
 extern FILE * fp_output;

#define TAB0 60 



//
//int comment_insn(char line[],
//				 unsigned int ip,
//				unsigned char *buffer,
//				int prefix_bytes,
//				int len,
//				char prefix,
//				int data_size,
//				int addr_size);

int comment_insn(char line[],PINSN_INFO insn);
void print_proc_info(unsigned int address);


static void disasm_insn(PINSN_INFO insn)
{
	char line[4000];
	int len;


	//
	//  if it is a proc, print parameter list
	//
	//
	// lookup the proc record
	//


	if(real_mode())
	{
		len=sprintf(line,"%04x:%04x ",(insn->basic_info.eip>>16),insn->basic_info.eip&0xffff);
	}
	else
		len=sprintf(line,"%08x  ",insn->basic_info.eip);


	//
	//  disasm
	//
	//
	// if function call,  gen html href
	//
	//if(insn->basic_info.p_instr_desc->index==callr)
	//{
	//	len+=sprintf(line+len,"<a href= #proc_%08x> ",insn->exec_info.imm);
	//}


	len+=disasm_line(line+len,&insn->basic_info);
		//real_mode()?(insn->basic_info.eip&0xffff):insn->basic_info.eip,
		//insn->basic_info.code, 
		//insn->basic_info.prefix_bytes, 
		//insn->basic_info.len, 
		//insn->basic_info.prefix,
		//insn->basic_info.data_size,
		//insn->basic_info.addr_size);
	//
	// padding
	//
	//
	// padding to TAB0
	//
	len--;// remove '\0'
	while (len<TAB0) line[len++]=' ';	
	line[len++]=';';

	//if(insn->basic_info.p_instr_desc->index==callr)
	//{
	//	len+=sprintf(line+len,"</a> ");
	//}
	////
	// comments;
	//
	//
	// for pe32, check importing function calling
	//
	char * pe32_check_imported_function_call(unsigned char *code);

	char *s=pe32_check_imported_function_call(insn->basic_info.code+insn->basic_info.prefix_bytes);
	if(s)
	{
		len+=sprintf(line+len,"(%s)",s);

	}
	else
	len+=comment_insn(line+len,insn);
	//len+=comment_insn(line+len,
	//	real_mode?insn->basic_info.eip&0xffff:insn->basic_info.eip,
	//	insn->basic_info.code, 
	//	insn->basic_info.prefix_bytes, 
	//	insn->basic_info.len,
	//	insn->basic_info.prefix,
	//	insn->basic_info.data_size,
	//	insn->basic_info.addr_size);

	line[len++]=0;

	fprintf(fp_output,"//%s\n",line);

	//
	// disasm_line only print the first 8 instruction bytes. if morethan 8 bytes, orint the rest in another line
	//
	if(insn->basic_info.len>8)
	{
		len=0;
		while(len<10) line[len++]=' ';


		for(int i=8;i<insn->basic_info.len;i++)
		{
			len+= sprintf(line+len,"%02x ",insn->basic_info.code[i]);
		}
		line [len]=0;
		fprintf(fp_output,"//%s\n",line);


	}


		//
		// testing operand info
		//
		//void dump_operand(PINSN_EXEC_INFO info);
		//dump_operand(&insn->exec_info);

}
static void  disasm_basic_block(PBASIC_BLOCK bb)
{
	//if(bb->gen_html_tag) fprintf(fp_output,"<a name=proc_%08x> </a>",real_mode()?bb->start&0xffff:bb->start);

	DLIST *p=bb->insn.next;
	//fprintf(fp_output,"dis bb:%04x,%04x,%04x,\n",bb,bb->start,bb-  >end);

	print_proc_info(real_mode()?bb->start&0xffff:bb->start);
	while(p!=&bb->insn)
	{
		PINSN_INFO q=(PINSN_INFO)(p+1);
		disasm_insn(q);

		p=p->next;
	}

}

static void print_ident(int n_ident)
{
	while(n_ident) {fprintf(fp_output,"    ");n_ident--;}
}

void output_bb(PBASIC_BLOCK p_bb,int n_ident )
{
	while(p_bb)
	{

		void reg_propagate_in_caller(PBASIC_BLOCK bb);

		reg_propagate_in_caller( p_bb);
		disasm_basic_block( p_bb);


		switch(p_bb->bb_type)
		{
		case BB_IF: 
		case BB_IFN: 

			//print_bb_insn(p_bb);
			
			print_ident(n_ident);
			fprintf(fp_output,"if (){\n"); 		
			output_bb(p_bb->p_bb_body,n_ident+1);
			
			print_ident(n_ident);
			fprintf(fp_output,"}\n");	
			break;
		case BB_IF_ELSE: 

			//print_bb_insn(p_bb);
			
			print_ident(n_ident);
			fprintf(fp_output,"if (){\n"); 
			output_bb(((PIF_ELSE_DAT)p_bb->p_ext_data)->p_bb_ntk,n_ident+1);
			
			print_ident(n_ident);
			fprintf(fp_output,"\n} else {\n"); 
			//print_bb_insn(p_bb);
			output_bb(((PIF_ELSE_DAT)p_bb->p_ext_data)->p_bb_tk,n_ident+1);
			
			print_ident(n_ident);
			fprintf(fp_output,"}\n");	
			break;
		case BB_FOR: 
			fprintf(fp_output,"for (){\n"); 
			break;
		case BB_WHILE_DO:
			//print_bb_insn(p_bb);
			print_ident(n_ident);
			fprintf(fp_output,"while (){\n"); 
			output_bb(((PWHILE_DAT)p_bb->p_ext_data)->p_bb_body,n_ident+1);
			print_ident(n_ident);
			fprintf(fp_output,"}\n"); 
			 break;
		case BB_DO_WHILE: 
			//print_bb_insn(p_bb);
			print_ident(n_ident);
			fprintf(fp_output,"do {\n"); 
			output_bb(((PWHILE_DAT)p_bb->p_ext_data)->p_bb_body,n_ident+1);

			//print_bb_insn(p_bb);
			print_ident(n_ident);
		    fprintf(fp_output,"} while ()\n");
			break;
		case BB_SEQ: 
		default:
			//print_ident(n_ident);
			//printf("{"); 
		//case BB_LOOP:
		//	printf("loop {"); 
			//print_bb_insn(p_bb);

			//print_ident(n_ident);
			//printf("}\n");	
			 break;
		}
		if(p_bb==p_bb->p_bb_follow)
		{
			break;
		}

		//if(p_bb->p_bb_follow==NULL&&p_bb->bb_type==0)
		//	p_bb=p_bb->tk_branch;
		//else
			p_bb=p_bb->p_bb_follow;

	}
}

void reg_propagate_in_caller(PBASIC_BLOCK bb);

void gen_c_output(PFUNC_DISASMINFO func)
{

	output_bb(func->first_bb,0);
}



//void zap()
//{
//	SLIST * p=bb_list;
//
//	while(p)
//	{
//		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);
//
//	
//		destroy_list_dl(&bb->insn);
//
//		p=p->next;
//	}
//	destroy_list(&bb_list);
//}

//
//void gen_disasm_output(PFUNC_DISASMINFO func)
//{
//
//	order_bb();
//	SLIST * p=func->bb_list;
//
//	while(p)
//	{
//		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);
//
//		reg_propagate_in_caller( bb);
//		disasm_basic_block( bb);
//
//		p=p->next;
//	}
//}