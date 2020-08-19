#include <stdlib.h>
#include <assert.h>
#include "adv-disasm.h"

// add insn to basic block
//
//
int add_insn(PBASIC_BLOCK bb,PINSN_BASIC_INFO p_insn_info)
{

		DLIST * p=add_node_dl(&bb->insn, sizeof(INSN_INFO));

		if (!p)return 0;

		PINSN_INFO insn=(PINSN_INFO)(p+1);
		insn->basic_info=*p_insn_info;


		predecode_insn(p_insn_info,&insn->exec_info);
		assert(insn->basic_info.p_instr_desc);
		return 1;
}
//
// new_basic_block
//
PBASIC_BLOCK add_basic_block(SLIST * p_bb_list,unsigned int start_eip)
{


	//assert((start_eip&0xffff)!=0x8a);
	//if((start_eip&0xffff)==0x8a)
	//{
	//	fprintf(fp_output,")_");
	//}
		//fprintf(fp_output,"add bb--%x\n",start_eip);
	//
	// alreadt exist?
	//
	SLIST * p=p_bb_list->next;
	PBASIC_BLOCK bb_split=(PBASIC_BLOCK)0,bb;
	while(p)
	{
	
		 bb=(PBASIC_BLOCK)(p+1);

		if(bb->start==start_eip) 
			return bb;

		if(bb->start<=start_eip&& start_eip<=bb->end) 
		{
			bb_split= bb; break;
		}

		p=p->next;
	}	
	
	//
	// if the first insn matchede insn, don't splt, return split_bb
	//
	DLIST *q=(DLIST *)0;
	if(bb_split) 
	{
		q=bb_split->insn.prev;
	
		//
		// move iinsns from start_eip to bb_split->end to new bb
		//
		PINSN_INFO insn;
		//
		// look for the 
		//
		while(q!=&bb_split->insn)
		{
			insn=(PINSN_INFO)(q+1);

			if (insn->basic_info.eip==start_eip)
					break;
			

			q=q->prev;
		}
		// if jump into a middle of a insn, q will be null, don't splt, disasm both bb
		// if the first insn matches,should be the same bb, won't reach here.

		if(q!=&bb_split->insn &&(q->prev==&bb_split->insn))
			return bb_split;
	}
	
	
	p=add_node(p_bb_list, sizeof(BASIC_BLOCK));

	if (!p)return 0;

	bb=(PBASIC_BLOCK)(p+1);
	INIT_DLIST(&bb->insn);
	bb->flag=0;   // not processed
	bb->p_bb_follow=bb->tk_branch=(PBASIC_BLOCK)0; //  branch targets unknown as yet
	//bb->p_func=p_func;
	bb->end=
	bb->start=start_eip;

	//
	// if we must split bb_clobbered
	//
	if(bb_split&&q!=&bb_split->insn)
	{	

		bb->p_bb_follow=bb_split->p_bb_follow;
		bb->tk_branch=bb_split->tk_branch;
		
		assert(q->prev!=&bb_split->insn);  // first  insn bb
		//assert(q->next!=&bb_split->insn);  // last  insn bb
		bb->end=bb_split->end;



		// move the insn after q to bb.
		bb->insn.prev=bb_split->insn.prev;
		bb->insn.prev->next=&bb->insn;

		// q's prev be the head of bb_split
		q->prev->next=&bb_split->insn;
		bb_split->insn.prev=q->prev;

		bb_split->end=((PINSN_INFO)(q->prev+1))->basic_info.eip|(real_mode()?(start_eip&0xffff000):0);
	
	
		
		// q is the first insn of bb
		q->prev=&bb->insn; // break the link
		bb->insn.next=q;
		bb->flag=1; // already processed.

		bb_split->p_bb_follow=bb;
		bb_split->tk_branch=(PBASIC_BLOCK)0;
	}

	return bb;
}
//
// split a bb from a given node
//
PBASIC_BLOCK split_bb(PFUNC_DISASMINFO p_func,PBASIC_BLOCK bb_split,DLIST *q)
{
	unsigned short seg16=real_mode()?(bb_split->start>>16):0;
	//
	// verify q is in bb_split
	//
	assert(bb_split);

	if(q->next==&bb_split->insn||q->prev==&bb_split->insn||q==&bb_split->insn)
	{
		assert(0);
	}
	
	DLIST *p=bb_split->insn.prev;
	//
	// look for the 
	//
	while(p!=&bb_split->insn)
	{
			if (p==q)break;
			q=q->prev;
	}
		// if jump into a middle of a insn, q will be null, don't splt, disasm both bb
		// if the first insn matches,should be the same bb, won't reach here.

	assert(p==q);
	assert(q!=&bb_split->insn);
	//
	// data valid, split the bb
	//
	SLIST *p_bb=add_node(&p_func->bb_list, sizeof(BASIC_BLOCK));
	assert(!p_bb);

	PBASIC_BLOCK bb=(PBASIC_BLOCK)(p_bb+1);
	INIT_DLIST(&bb->insn);
	bb->flag=0;   // not processed
	bb->p_bb_follow=bb->tk_branch=(PBASIC_BLOCK)0; //  branch targets unknown as yet
	//bb->p_func=p_func;
	bb->start=((PINSN_INFO)q->prev)->basic_info.eip;

	//
	// if we must split bb_clobbered
	//

	bb->p_bb_follow=bb_split->p_bb_follow;
	bb->tk_branch=bb_split->tk_branch;
	
	assert(q->prev!=&bb_split->insn);  // first  insn bb
	//assert(q->next!=&bb_split->insn);  // last  insn bb
	bb->end=bb_split->end;



	// move the insn after q to bb.
	bb->insn.prev=bb_split->insn.prev;
	bb->insn.prev->next=&bb->insn;

	// q's prev be the head of bb_split
	q->prev->next=&bb_split->insn;
	bb_split->insn.prev=q->prev;


	bb_split->end=((PINSN_INFO)(q->prev+1))->basic_info.eip|(real_mode()?(seg16<<16):0);

	
	// q is the first insn of bb
	q->prev=&bb->insn; // break the link
	bb->insn.next=q;
	bb->flag=1; // already processed.

	bb_split->p_bb_follow=bb;
	bb_split->tk_branch=(PBASIC_BLOCK)0;
	
	return bb;
}

PBASIC_BLOCK lookup_basic_block(PFUNC_DISASMINFO func,unsigned int start_eip)
{
	SLIST *p=func->bb_list.next;

	while(p)
	{
		 PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		if(bb->start==start_eip) 
			return bb;

		p=p->next;
	}	
	return (PBASIC_BLOCK)0;
}

PBASIC_BLOCK get_basic_block_by_flag( PFUNC_DISASMINFO func,int flag_to_match)
{
	SLIST * p=func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		if(bb->flag==flag_to_match) return bb;

		p=p->next;
	}
	return (PBASIC_BLOCK)0;
}

void reset_basic_block_counter( PFUNC_DISASMINFO func)
{
	SLIST * p=func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		bb->count=0;

		p=p->next;
	}
}

void reset_basic_block_flag( PFUNC_DISASMINFO func, unsigned int mask)
{
	SLIST * p=func->bb_list.next;

	while(p)
	{
		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);

		bb->flag &=~mask;

		p=p->next;
	}
}


SLIST * order_bb(SLIST *bb_list)
{
	SLIST *q=NULL,*r=NULL,*p;

	while(p=bb_list)
	{
		// detach from data_list
		bb_list=bb_list->next;

		PBASIC_BLOCK bb=(PBASIC_BLOCK)(p+1);
		unsigned long addr=bb->start;
		//
		//  add to q
		//
		r=q;
		
		if(NULL==q) {q=p;p->next=NULL;continue;}
		if(addr<((PBASIC_BLOCK)(q+1))->start)
		{
			p->next=q;
			q=p;
			continue;
		}
		while(r->next)
		{
				bb=(PBASIC_BLOCK)(r+1);
				PBASIC_BLOCK bb1=(PBASIC_BLOCK)(r->next+1);
				if(addr>bb->start&&addr<=bb1->start) break;	
				r=r->next;
		}
		p->next=r->next;
		r->next=p;
	}

	return q;
}





void strip_epilog_bb(PFUNC_DISASMINFO p_func)
{
	PBASIC_BLOCK p_bb=NULL;

	SLIST  *p=p_func->bb_list.next,*q=NULL;

	while(p)
	{
		p_bb=(PBASIC_BLOCK)(p+1);
		//
		// epilog bb, don't care about it
		//
		if(NULL==p_bb->tk_branch&&NULL==p_bb->p_bb_follow) break;
		q=p;
		p=p->next;
	}
	//
	// drop q
	//
	if(!p)return; // not found ; error
	else if(q)// found in middle
	{
		assert(q->next);
		q->next=q->next->next;
	}
	else // found at head
	{
	}
}