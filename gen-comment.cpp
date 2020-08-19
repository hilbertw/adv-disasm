#define   _CRT_SECURE_NO_DEPRECATE 1
#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string.h>

#include "adv-disasm.h"



#define GREG8 0
#define GREG16 1
#define GREG32 2
#define REGSEG 3
#define REGCR 4
#define REGDR 5
#define REGTR 6


struct comment_info
{
	int type;
	unsigned int data;
} comment_set[5];
int num_comments;

void comment_imm(unsigned int imm)
{
	comment_set[num_comments].type=0;
	comment_set[num_comments++].data=imm;
	//printf(" imm:%x\n",imm);
}

void comment_mem(unsigned int address)
{
	comment_set[num_comments].type=1;
	comment_set[num_comments++].data=address;
	//printf("data addr:%x\n",address);

}

void comment_disp(unsigned int disp)
{
	comment_set[num_comments].type=2;
	comment_set[num_comments++].data=disp;
	//printf("disp addr:%x\n",disp);

}

void comment_port(unsigned int port )
{
	comment_set[num_comments].type=3;
	comment_set[num_comments++].data=port;
	//printf("port addr:%x\n",port);
}
void comment_proc(unsigned int address )
{
	comment_set[num_comments].type=4;
	comment_set[num_comments++].data=address;
	//printf("port addr:%x\n",address);
}
void comment_int(unsigned int int_no )
{
	comment_set[num_comments].type=5;
	comment_set[num_comments++].data=int_no;
	//printf("int :%x\n",int_no);
}
void comment_reg( int reg, int type )
{
	comment_set[num_comments].type=6;
	comment_set[num_comments++].data=(type<<16)|(reg&0xffff);
	//printf("reg addr:%x,%x\n",reg,type);
}


void  comment_oper(
	unsigned char  *code,  // not including 0x0f if two bytes opcode instructions
	int next_ip,
	int address_size,
	int data_size,
	int override_seg,
	int flag );


int comment_Mv(
	unsigned char  *code, 
	int address_size,
	int data_size_num,
	int override_seg );

int comment_Ev(
	unsigned char  *code, 
	int address_size,
	int data_size,
	bool word,
	int override_seg,
	bool disp_dsize=false );

int comment_Rv(
	int reg,
	int data_size,
	bool word);


int comment_EvGv(
	unsigned char  *code, 
	int address_size,
	int data_size,
	bool word,
	bool dir,
	int override_seg );


int comment_line(	
	unsigned char * code,
	int next_ip,
	prefix_t prefix,
	int data_size,
	int addr_size,
	 struct instr_rec* instr_desc);


//
// may be bug here. all w_mask is 1?
//
static void  comment_acc(bool word,int data_size)
{
	comment_reg(0,word?((data_size==32)?GREG32:GREG16):GREG8);
}
static unsigned long comment_regIv(int reg, bool word, unsigned char * code, int data_size)
{
	unsigned long imm;

	if(word) {// imm
	if(data_size==32)
		imm=*(unsigned long *)(code+1);
	else
		imm=*(unsigned short *)(code+1);
	}
	else
	imm=code[1];


	comment_imm(imm);
	return imm;
}
//
// MOV -- Move to/from Special Registers
//
// explain cr3, cr2,cr0

static int comment_cr_r( bool dir, unsigned char * code, char c)
{
	//greg=(code[1]>>3)&7;
	//creg=code[1]&7;

	//if(dir)
	//else 

	return 0;
}
//
//
//
// flag:    1-- dir
//          2-- word
//			3-- sign extension
// 

int comment_operands(
	unsigned char  *code, // not including 0x0f if two bytes opcode instructions
	int next_ip,
	int addr_size,
	int data_size,
	int override_seg ,
	int flag,
	OP_FMT  op_fmt)
{
	unsigned int imm;

	switch(op_fmt)
	{

	case dx_acc	   :
	//
	// comment dx,
	// comment ports
	// comment value of acc
	//
	comment_acc(0!=(flag&2),data_size);
	break; 
case accEv	   :
	break; 
case accIb	   :
	// in al,imm8
	//
	// comment ports
	comment_port(code[1]);
	comment_acc(0!=(flag&2),data_size);
	break; 

case accIv 	   :
	if(flag&2) {// imm
		imm=(data_size==32)?*(unsigned long *)(code+1):*(unsigned short *)(code+1);
	}
	else
		imm=code[1];

	comment_imm(imm);
	break;   
case accReg	   :
	//
	// only xchg acc,r16/32,word mask is 1
	//
	// comment acc
	comment_acc(0!=(flag&2),data_size);
	if(flag&2)
	{
		comment_reg(code[0]&7,(data_size==32) ?GREG32:GREG16);
	}
	else
		comment_reg(code[0]&7,GREG8);

	break;    
case accXv     :
	break;  
case Ap	       :
	//
	// won't comment
	//
	// if(data_size==32) {
	// seg=*(unsigned short *)(code+5);ip=*(unsigned long *)(code+1));
	// }else {
	// seg=*(unsigned short *)(code+3);ip=*(unsigned short *)(code+1));
	// }

	break;     
case DXXv      :
	break;    
case Eb		   :
		comment_Ev(
		code, 
		
		 addr_size,
		data_size,     
		false,                // rm8
		 override_seg );
	   
	break;    
case Ep		   :

	comment_Mv(
		code, 
		
		 addr_size,
		4,          // far ptr
		 override_seg );
	break;     
case Ev		   :

	 comment_Ev(
		code, 
		
		 addr_size,
		 data_size,
		2==(flag&2),          //word
		 override_seg );
	break;     
case Ev1	   :
	 comment_Ev(
		code, 
		
		 addr_size,
		 data_size,
		2==(flag&2),          //word
		 override_seg );

	break;    
case EvCL	   :
	 comment_Ev(
		code, 
		
		 addr_size,
		 data_size,
		2==(flag&2),          //word
		 override_seg );
	//
	// comment cl's value
	//
	comment_reg(1,GREG8);// reg no of CL is 1
	break;    
case EvGv	   :

	 comment_EvGv(
		code, 
		
		addr_size,
		data_size,
		0!=(flag&2),
		0!=(flag&1),
		override_seg );

	break;  
case EvvGv:
	//
	// movzx/movsx
	//
	// commment source
	//

	 comment_Ev(
		code, 
		
		 addr_size,
		  16,
		  0!=(flag&2),
		 override_seg,
		 true );

break;


case EvGvCL	   ://shrd
	 comment_EvGv(
		code, 
		
		addr_size,
		data_size,
		0!=(flag&2),
		0==(flag&1),
		override_seg );
	//
	// comment cl's value
	//
	comment_reg(1,GREG8);// reg no of CL is 1
	break;    
case EvGvIb    :
	 comment_EvGv(
		code, 
		
		addr_size,
		data_size,
		0!=(flag&2),
		0!=(flag&1),
		override_seg );

	goto comment_Ib_after_Ev;

	break;    
case EvGvIv	   :
	 comment_EvGv(
		code, 
		
		addr_size,
		data_size,
		0!=(flag&2),
		0!=(flag&1),
		override_seg );
	goto comment_Iv_after_Ev;
	break;    

case EvIb	   :
	 comment_Ev(
		code, 
		
		 addr_size,
		data_size,     
		0!=(flag&2),                // rm16/32
		 override_seg,true );

comment_Ib_after_Ev:
	{
		unsigned char * imm=code +((addr_size==32)?decode_len_mm_noimm_32(code+1):(addr_size==16)?decode_len_mm_noimm_16(code+1):0);

		 comment_imm( imm[0]);
	}
	break;   
case EvIv	   :

	 comment_Ev(
		code, 
		
		 addr_size,
		data_size,     
		2==(flag&2),                // rm16/32
		 override_seg,true );

comment_Iv_after_Ev:
	{
		unsigned char * p_imm=code +((addr_size==32)?decode_len_mm_noimm_32(code+1):(addr_size==16)?decode_len_mm_noimm_16(code+1):0);
		if(2==(flag&6))
		{// imm
			if(data_size==32)
				imm=*(unsigned long *)p_imm;
			else
				imm=*(unsigned short *)p_imm;
		}
		else
			imm=p_imm[0];

		 comment_imm( imm);
	}
	break;    
case Ew		   :
	 comment_Ev(
		code, 
		
		 addr_size,
		16,     
		true,                // rm16
		 override_seg );
	   
	break;    
//case EwRw	   :
//	break;    
case FSGS	   :
	//
	// only push/pop fs/gs0xa0/push fs 0xa1/pop fs
	//
	// comment value of fs,gs if known
	break;    
case Fv		   :
	break;    
case GvEw      :
	break;    

	break;    
case GvMv      :
case GvMa	   :
case GvMp	   :

	 comment_EvGv(
		code, 
		
		addr_size,
		data_size,
		true,
		true,
		override_seg );
	break;    
case Ib		   :
	// int xx
	// comment int 10h
	comment_int(code[1]);
	break;    
case Ibacc	   :
	// out imm8,acc
	// comments ports
	// comment acc
	comment_port(code[1]);
	comment_acc(0!=(flag&2),data_size);
	break;    
case fmt_int3	   :
	//
	// won't comment
	//
	break;    
case Iv		   :
	//push Iv
	//
	// if word
	//
	if(flag &2)
	{
		imm=(data_size==32)?*(unsigned long *)(code+1):*(unsigned short *)(code+1);
	}
	else
		imm=code[1];
	comment_imm( imm);
	break;    
case Iw		   :
	// rern xx
	//
	// won't comment, length of all parameters
	// imm=*(unsigned short *)(code+1));
	break;    
case IwIb	   :
	//
	// won't comment. enter x,y
	// frame_size=*(unsigned short *)(code+1)
	// level=*(unsigned char *)(code+3));
	break;    
case Jb		   :
	if(data_size==32)
	imm=next_ip+(char)code[1];
	else
	imm=(next_ip+(char )code[1])&0xffff;

	comment_proc(imm);
	break;    
case Jv		   :
	if(data_size==32)
	imm= next_ip+*(long *)(code+1);
	else
	imm=(next_ip+*(short *)(code+1))&0xffff;

	comment_proc(imm);
	break;    

case Mp		   :
	 comment_Mv(
		code, 
		
		 addr_size,
		4,          //far ptr
		 override_seg );
	break;    
case Ms		   :
	 comment_Mv(
	 code, 
	 
	 addr_size,
	 -1, // don't display byte ptr etc.
	 override_seg );
	break;    
case Ovacc	   :
	//
	// comment memory
	//
	if(addr_size==32) imm= *(unsigned long *)(code+1);
	else imm=*(unsigned short *)(code+1);

	//if(override_seg==DS||(override_seg==7))
	//{
	//}
	//else
	//{
	//}
	comment_mem(imm);
	//
	// comment acc if it is source
	//
	if(flag &1) 
	{
		comment_acc(0!=(flag&2),data_size);
	}

	break;    
case RdCd	   :
	 comment_cr_r((flag &1),code,'c'); 
	break;    
case RdDd	   :
	 comment_cr_r((flag &1),code,'d'); 
	break;    
case RdTd	   :
	//
	// comment register
	//
	 comment_cr_r((flag &1),code,'t'); 
	break;    
case fmt_REG	   :
	//
	// dec/inc/push/pop r16/32
	//
	 comment_reg(code[0]&7, (data_size==32)?GREG32:GREG16);
	break;    
case regIv	   :
	//
	// 
	//
	 comment_regIv(code[0]&7,0!=(flag&2),code,data_size);
	break;    
case fmt_SREG	   :
	//
	//only in push/pop,bit3/4
	// comment segment register
	comment_reg((code[0]>>3)&3, REGSEG);
	break;    
case SwEw      :
	// GREG16<->sreg
	// comment siurce
	if(flag &1)
	{
		 comment_Ev(
			code, 
			
			 addr_size,
			16,     
			true,                // rm16
			 override_seg );
	}
	else 
	{
		// comment segment register
		comment_reg((code[1]>>3)&7, REGSEG);
	}
	break;    
case XvYv      :
	break;    
case Yvacc     :
	break;    
case YvDX      :
	break;    
	}

	return 0;
}



int comment_line(	
	unsigned char * code,
	int next_ip,
	prefix_t prefix,
	int data_size,
	int addr_size,
	 struct instr_rec* instr_desc)
{
	if(code[0]==0x0f) 
		code ++;
	//
	//prepare to print operands;
	//
	int flag =0;
	// gen flag:1-- dir prersents
	//          2-- word prersent
	//			3-- sign extension prersents
	// 
	if (0!=instr_desc->dir_mask&&
		(0!=(code[0]&instr_desc->dir_mask))
		)
		flag |=1;

	if (0==instr_desc->w_mask||
		//(code[0]==0x0f&&0!=(code[1]&instr_desc->w_mask))||
		(/*code[0]!=0x0f&&*/0!=(code[0]&instr_desc->w_mask))
		)
		flag |=2;

	if (instr_desc->sext_mask&&
		(0!=(code[0]&instr_desc->sext_mask))
		)
		flag |=4;

	//
	//print operands;
	//
	comment_operands(
		code, 
		next_ip,
		addr_size,
		data_size,
		(prefix &7),
		flag,
		instr_desc->op_fmt);

	return 0;
}

//
// be called after disasm_line. so that instr_desc has  right values
//
char * lookup_enum(unsigned int address, unsigned int data);
char * lookup_data(unsigned int address);
char * lookup_comments(unsigned int address);
char * lookup_struct(unsigned int address, unsigned int disp);
char * lookup_proc_name(unsigned int address);
int print_data_name( char *buffer,unsigned int address);
int print_struct_name( char *buffer,unsigned int address,unsigned int  disp);
int detect_string(char * line,unsigned int address);
bool pe32_map_data(unsigned int virtualAddress,unsigned int size);
extern char * data_base;
extern int dataseg_base;
extern unsigned int addr_base,dataseg_size;
int comment_insn(char line[],PINSN_INFO insn)
{
		 unsigned char * &code=insn->basic_info.code;
		 unsigned int &eip=insn->basic_info.eip;
		 unsigned int next_ip=insn->basic_info.eip+insn->basic_info.len;

		next_ip=real_mode()?(next_ip&0xffff):next_ip;
		int ip=real_mode()?(eip&0xffff):eip;
		num_comments=0;

		comment_line(	
		insn->basic_info.code +insn->basic_info.prefix_bytes,
		 next_ip,    // next ip, for relative branch lines
		 insn->basic_info.prefix,
		 insn->basic_info.data_size,
		 insn->basic_info.addr_size,
		 insn->basic_info.p_instr_desc);

		//if(!num_comments)
		//{
			comment_set[num_comments].type=7;
			comment_set[num_comments++].data=ip;
		//}
		//
		// print comments
		//
		int i,ret_len=0;
		char *s;


		for(i=0;i<num_comments;i++)
		{
			switch(comment_set[i].type)
			{
			case 0: // imm
				//
				// lookup type, if a enum type is seen, convert imm to enum symbol
				//
				s=lookup_enum(ip,comment_set[i].data);
				if(s) break;
				s=lookup_comments(ip);
				if(s) break;
				// byte imm, printable letter? 
				if((comment_set[i].data>=' '&&comment_set[i].data< 127)){	ret_len+=sprintf(line+ret_len,"'%c'",comment_set[i].data&0xff);continue;}
				else if(pe32_mode()) ret_len+=detect_string(line+ret_len,comment_set[i].data);
			case 1: // mem
				//
				// lookup data, print variable name
				//
				ret_len+=print_data_name(line+ret_len,comment_set[i].data);
				//
				// if pe32,
				//
				if(pe32_mode()&&pe32_map_data(comment_set[i].data,4)&&comment_set[i].type!=0)
					ret_len+=sprintf(line+ret_len,";dd %08x",*(int *)(data_base+comment_set[i].data-addr_base+dataseg_base));

				continue;
			case 2: // disp
				//
				// lookup type, if a union/struct type is seen, convert imm to member symbol
				//
				ret_len+=print_struct_name(line+ret_len,real_mode()?ip&0xffff:ip,comment_set[i].data);
				continue;


			case 7: // comments
				//
				// lookup proc, print prrocedure name
				//
				s=lookup_comments(comment_set[i].data);
				if(!s) s=insn->comments;
				break;
			case 4: // proc
				//
				// lookup proc, print prrocedure name
				//
				s=lookup_proc_name(comment_set[i].data);
				break;
			case 3: // port
			case 5: // int
			case 6: // reg
			default:
					s=NULL;
				break;
			}
			if(s)
			ret_len+=sprintf(line+ret_len,";%s",s);
		}
		//
		// display type, comments
		//
		if( insn->op_type) ret_len+=sprintf(line+ret_len,";%s",insn->op_type->identifier);



		return ret_len;
}
int pe32_get_max_strlen(unsigned int virtualAddress);

int detect_string(char * line,unsigned int address)
{
	//
	// push imm, print string
	//
	int ret_len=0;
	int max_len;
	max_len=pe32_get_max_strlen(address);

	if(max_len)
	{
		extern char * data_base;
		extern int dataseg_base;
		extern unsigned int addr_base,dataseg_size;

		unsigned char * data_ptr=(unsigned char * )data_base+address-addr_base+dataseg_base;

		int i;
		if(data_ptr[1]==0) // wchar
		{
			unsigned short * wdata_ptr=(unsigned short  *)data_ptr;
			max_len>>=1;
			// if the first 10 chars are printable, print thestring
			for(i=0;i<10&& i<max_len;i++) if(wdata_ptr[i]<' '||wdata_ptr[i]>0x7f) return 0;
			sprintf(line+ret_len,";");
			for(i=0;i<max_len&&data_ptr[i];i++)
				ret_len+=sprintf(line+ret_len,data_ptr[i]<' '?"\\x%04x":"%c", data_ptr[i]);
		}
		else
		{
			// if the first 10 chars are printable, print thestring
			for( i=0;i<10&& i<max_len;i++) if(data_ptr[i]==0||data_ptr[i]>'z') return 0;

			ret_len+=sprintf(line+ret_len,";");
			for(i=0;i<max_len&&data_ptr[i];i++)
			ret_len+=sprintf(line+ret_len,data_ptr[i]<' '?"\\x%02x":"%c", data_ptr[i]);
		}
	}
		return ret_len;
	}
