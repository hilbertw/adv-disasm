#define _CRT_SECURE_NO_WARNINGS 1
#include <stdlib.h>
#include <stdio.h>
#include "pe32.h"
#include "common.h"
#include "ifetcher.h"
#include "util.h"
#include "adv-disasm.h"
#include "guidinfo.h"



static SLIST function_list,pending_dat ;
//
// success: true
//

bool  check_pe32_thunk(unsigned int virtualAddress);

bool add_function(unsigned int addr)
{
	SLIST* p=function_list.next;

	//
	// already exists?
	//
	while(p)
	{
		if (addr==((FUNC_DISASMINFO *)(p+1))->addr) return true;
		p=p->next;
	}

	if(pe32_mode())check_pe32_thunk(addr);

	p=add_node (&function_list,sizeof (FUNC_DISASMINFO ));
	if (!p)return false; 
	
	((FUNC_DISASMINFO *)(p+1))->addr=addr;
	((FUNC_DISASMINFO *)(p+1))->processed=false;
	return true;
}
bool function_added(unsigned int addr)
{	
	SLIST* p=function_list.next;
	FOREACH_BEGIN(p,PFUNC_DISASMINFO,p_func)

		if(p_func->addr==addr) break;

	FOREACH_END(p)

	return p!=NULL;
}


bool find_basic_blocks(CIFetcherMemory fetcher,FUNC_DISASMINFO *func)
{
	unsigned int addr=func->addr;

	PBASIC_BLOCK bb;
	//printf("--%x\n",addr);
	func->first_bb=
	bb=add_basic_block(&func->bb_list,addr);

	while(bb)
	{
		unsigned int ip;

		bb->flag=1;
		addr=bb->start;

		unsigned short seg=real_mode()?(addr>>16):0;
		ip=real_mode()?(addr&0xffff):addr;
		//
		// if pe32, do we need to map to different section
		//
		int check_pe32_address(unsigned int ip);
		if(pe32_mode()&&check_pe32_address(ip))
		{
			bb->end=addr;
			goto next_bb;// code not found in pe32 sections.try next bb 
		}

		if (!fetcher.set_fetch_address(real_mode(),ip,seg))
		{
			bb->end=addr;
			goto next_bb;// code out of range.try next bb 
		}


		unsigned char*code;
		//int len;
		//char  prefix;
		//int data_size;
		//int addr_size;
		unsigned int next_ip;
		INSN_BASIC_INFO insn;

		do {
			// fetch an instruction
			int ret =fetcher.fetch(&insn);
			if (ret==2) break;// end of input stream
			if (ret!=FETCH_SUCCESS) break;// end of input stream



			code=insn.code+insn.prefix_bytes;
			next_ip=insn.eip+insn.len;
			unsigned int linear_address;
			//
			//
			// may be the end of the bb.
			//bb->end=real_mode()?((seg<<16)+(ip&0xffff)):ip;

			if(/*bb->start==0x46b8
				|| */insn.eip==0x48cc)
				printf("");

			//
			// Basic block ends/start with branchs, jcc: adds two pending branches.
			//
			int rel=
				((code[0]&0xf0)==0x70)?(char)code[1]: // jcc
				((code[0]&0xfc)==0xe0)?(char)code[1]: // jcxz,loopcc
				((code[0]==0x0f)&&(code[1]&0xf0)==0x80)?((insn.data_size==32)?*(int *)(code+2):*(short *)(code+2)):0;
				

			if (rel)
			{
				unsigned int target_ip=next_ip+rel;

				PBASIC_BLOCK p_bb=add_basic_block (&func->bb_list,insn.eip);
				p_bb->flag |=BB_FLAG_PROCESSED|BB_FLAG_CB;
			
				if(rel<0) p_bb->flag|=BB_FLAG_LOOP;

				add_insn(p_bb,&insn);

				bb->p_bb_follow=p_bb;

				p_bb->tk_branch=add_basic_block (&func->bb_list,target_ip);
				p_bb->p_bb_follow=add_basic_block (&func->bb_list,next_ip);
				break;
	
			}
			//
			// Basic block ends/start with branchs, jmp rel8/rel16/rel32?.
			//

			else if((code[0]&0xfd)==0xe9)
			{
				unsigned int target_ip;
				
				
				if(code[0]==0xe9) target_ip=next_ip+((insn.data_size==32)?*(int*)(code+1):*(short*)(code+1));
				else target_ip=next_ip+(char)code[1];

				linear_address=target_ip;

				if(bb->start!=insn.eip)
				{
					PBASIC_BLOCK p_bb=add_basic_block (&func->bb_list,insn.eip);

					p_bb->flag |=BB_FLAG_PROCESSED|BB_FLAG_UB;
				
					bb->p_bb_follow=p_bb;

					add_insn(p_bb,&insn);

					if(!function_added(linear_address)) 
						p_bb->tk_branch=add_basic_block (&func->bb_list,linear_address);
				}


				break;
			}

			add_insn(bb,&insn);
			//
			// jmp ptr16:16 or ptr32:16
			// 
			//
			//else if(code[0]==0xea)
			//{
			//	//unsigned int target_ip=((data_size==32)?*(unsigned int*)(code+1):*(unsigned short*)(code+1));
			//	unsigned int target_addr=*(unsigned int*)(code+1);

			//	add_function (&function_list,target_addr);
			//	break;
			//}
			//
			// call xx. add a new pending func node
			//
			if (code[0]==0xe8) //call
			{
				rel=((insn.data_size==32)?*(int*)(code+1):*(short*)(code+1));

				unsigned int target_ip=next_ip+rel;
				add_function (target_ip);		
			}

			//
			// ret,retn,retf,retfn,iret ends a func
			//
			if ((code[0]==0xc3)	
				||(code[0]==0xcb)
				||(code[0]==0xc2)
				||(code[0]==0xca))
			{


				bb->flag|=BB_FLAG_RET;
				break;
			}
			//
			// basic block stops at data.next ip has beend tagged data?
			//
			linear_address=real_mode()?((seg<<16)+(next_ip&0xffff)):next_ip;
			if( lookup_datarec(next_ip)) break;
			if(function_added(linear_address)) break;

			if( bb->p_bb_follow=lookup_basic_block(func,next_ip)) break;

		} while (1);  // until ret fetched

		DLIST *p=bb->insn.prev;
		if(p!=&bb->insn)
			bb->end=((INSN_BASIC_INFO*)(p+1))->eip;

		// get basic block with flag=0;
next_bb:
		bb=get_basic_block_by_flag(func,0);
	}
	return 0;
}
//void disasm_basic_blocks();

void collect_function_info(PFUNC_DISASMINFO p);
void zap();
bool disasm_func(CIFetcherMemory fetcher,unsigned int addr)
{
	//
	// add ip to pending func
	//
	if(!add_function (addr)) 
		return 0;
	

	int  function_not_scan_found=1;
	while(function_not_scan_found)
	{

		SLIST* func=function_list.next;
		function_not_scan_found=0;
		while(func)
		{
			if (!((FUNC_DISASMINFO *)(func+1))->processed) 
			{
				function_not_scan_found++;

				((FUNC_DISASMINFO *)(func+1))->processed=true;
				//
				// initialize 
				//

				//
				// finding out basic blocks
				//
				find_basic_blocks( fetcher, (FUNC_DISASMINFO *)(func+1));
				//
				// analyze
				//

				//
				// cleanup
				//
			}
			func=func->next;
		}
	}
	return 1;
}


char * pe32_lookup_exported_func(unsigned long  address);

static int unnamed_fun_num;
void collect_function_info(PFUNC_DISASMINFO p)
{

	//
	// proc_rec?
	//
	PPROCEDURE_REC proc_rec=lookup_proc(p->addr);

	char * func_name;
	PFUNCTION_INFO  func_prototype=NULL;
	
	//
	// if pe32, is it an exported api?
	//
	if(pe32_mode()) 
		func_name= pe32_lookup_exported_func(p->addr);
	else func_name= NULL;

	if(func_name) 
	{
		p->exported=1;
		p->name=func_name;
		func_prototype=lookup_function(func_name);
	
	}
	else if(proc_rec)
	{
		p->name=proc_rec->name;

		if(!func_prototype) 
			func_prototype=lookup_function(proc_rec->name);
	}
	else
	{
		char buffer[20];
		p->name=put_string( buffer,sprintf(buffer,"func_%d",unnamed_fun_num++));
	}

	
	//
	// a function proto type is known?get c parameter ist  or asm register para list
	//
	
	if(func_prototype)
	{
		p->parameter_list=func_prototype->parameter_list;
		p->type=PROC_TYPE_CFUNCTION;
		if( proc_rec )
			p->var_list= proc_rec->var_list;
	}
	else if( proc_rec )
	{
		p->type=proc_rec->type;

		if(proc_rec->type==PROC_TYPE_ASMPROC)
			p->parameter_list= proc_rec->parameter_list;
		else
			p->var_list= proc_rec->var_list;

	}
	else
	{
		p->type=PROC_TYPE_ASMPROC;
	}
}


void do_disasm ()
{
	SLIST* func=function_list.next;
	while(func)
	{

		extern FILE *fp_output;

		char buffer[MAX_PATH];

		FUNC_DISASMINFO *p_func=(FUNC_DISASMINFO *)(func+1);
		collect_function_info(p_func);


		if(p_func->type==PROC_TYPE_CFUNCTION)
		{
			if(real_mode())sprintf(buffer,"%04x-%04x.c",((FUNC_DISASMINFO *)(func+1))->addr>>16,((FUNC_DISASMINFO *)(func+1))->addr&0xffff);
			else
			sprintf(buffer,"%08x.c",((FUNC_DISASMINFO *)(func+1))->addr);
		}else
		{
			if(real_mode())sprintf(buffer,"%04x-%04x.asm",((FUNC_DISASMINFO *)(func+1))->addr>>16,((FUNC_DISASMINFO *)(func+1))->addr&0xffff);
			else
			sprintf(buffer,"%08x.asm",((FUNC_DISASMINFO *)(func+1))->addr);
		}

		fp_output=fopen(buffer,"wt");
		if(!fp_output)
		{
			printf("can not write to file:%s\n",buffer);
		}


		p_func->bb_list.next=order_bb(p_func->bb_list.next);
		if(p_func->type==PROC_TYPE_CFUNCTION)
		{
			//void c_analyze(PFUNC_DISASMINFO p);
			//void asm2c_func (FUNC_DISASMINFO *p_func);
			//void gen_c_output(PFUNC_DISASMINFO p);
			void gen_disasm_output(PFUNC_DISASMINFO p);

			gen_disasm_output(p_func);
			//c_analyze(p_func);
			//asm2c_func(p_func);

			//gen_c_output(p_func);

		}
		else
		{
			void asm_analyze(PFUNC_DISASMINFO p);
			void gen_disasm_output(PFUNC_DISASMINFO p);

			asm_analyze(p_func);
			gen_disasm_output(p_func);
		}

		fclose(fp_output);

		//printf(".disasm %x\n",((FUNC_DISASMINFO *)(func+1))->addr&(real_mode()?0xffff:0xffffffff));
		func=func->next;
	}
}