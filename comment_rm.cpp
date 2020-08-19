#define _CRT_SECURE_NO_WARNINGS



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

void comment_port(unsigned int port );
void  comment_disp(unsigned int imm );
void  comment_mem(unsigned int imm );
void comment_proc(unsigned int imm );
void comment_int(unsigned int int_no );
void comment_reg( int reg, int type );

int comment_Mv16( unsigned char  *code)
{
	 unsigned int disp;

     //
	 //
	 // base_reg=code[1]&7]);
     //
     switch((code[1]>>6)&3)
     {
      case 0:
          if((code[1]&7)==6)  //[disp16]
		  {
			  comment_mem(*(unsigned short*)(code+2));
			  return 0;
		  }
		  
		  disp=0;
		  break;

      case 1:
          disp=code[2];
		  break;
      case 2:
          disp=*(short*)(code+2);
		  break;
      case 3:
          return 0;            // reportr illegal instruction
     }
	 comment_disp(disp);
     return 0;
}

int comment_sib( unsigned char  *code)
{
    //
	// mm=0, sib.base==5. disp32[index]
	//
	if(0==(code[1]>>6)&&5==(code[2]&7))
	{
		//unsigned int disp32=*(unsigned int*)(code+3);

		//
		// scale==0? don't display *1
		//
		//index_reg=(code[2]>>3)&7;
		//scakle=1<<((code[2]>>6)&7);

	}
	else
	{
		//
		// scale==0? don't display *1
		//
		//base_reg=code[2]&7;
		//index_reg=reg16_name[(code[2]>>3)&7;
		//scale=1<<((code[2]>>6)&7):
	}
	
	return 0;
}

int comment_Mv32( unsigned char  *code)
{
     int len=0;
	 unsigned int disp;
	int sib;
	 //
	 //sib?
	 //
	sib=(4==(code[1]&7));
	//if(sib)
	//len =comment_sib(code,buffer);
	// else base_reg=code[1]&7];


     switch((code[1]>>6)&7)
     {

      case 0:
          if((code[1]&7)==5)           // [disp32]
		  { comment_mem(*(int*)(code+2));return 0;}
		  else if (sib&&(5==(code[2]&7)))// disp32[index]
			  disp=*(int*)(code+2);
		   else
			  disp=0;

		  break;

      case 1:
		  disp=sib?code[3]:code[2];
		  break;
      case 2:
		  disp=sib?*(int*)(code+3):*(int*)(code+2);
		  break;
      case 3:
          return 0;            // reportr illegal instruction
     }
	 //
	 // 
	 //
	 comment_disp(disp);
	 return len;
}


int comment_Mv(
	unsigned char  *code, 
	int address_size,
	int data_size_num,
	int override_seg )
{
	//
	// check whether segment overriden
	//
	// if(override_seg!=NO_SEGOVR)
	// {
	//    int flag=0;
	//    if (  (address_size==16&&is_stack16(code))
	//    	||(address_size==32&&is_stack32(code)))
	//    {
	//	     flag= (override_seg!=SS);
	//    }
	//    else
	//	    flag= (override_seg!=DS);

	return (address_size==16)?comment_Mv16(code):
		   (address_size==32)?comment_Mv32(code):0;

}

int comment_Rv(
	int reg,
	int data_size,
	bool word)
{
	return 0;

}

int comment_Ev(
	unsigned char  *code, 
	int address_size,
	int data_size,
	bool word,
	int override_seg,
	bool disp_dsize)
{

	//
	// if is a memory
	//
	if ( ((code[1]>>6)&3)!=3)
	
		comment_Mv(
			code, 

			 address_size,
			 (!disp_dsize)?-1:
			 (!word)?0:
			 (data_size==8)?0:
			 (data_size==16)?1:
			 (data_size==32)?2:
			 -1,

			 override_seg );
		
	 else
		//
		//it is a register
		//
		 comment_Rv(
			code[1]&7, 
			data_size,
			 word);
			

	return 0;
}

int comment_EvGv(
	unsigned char  *code, 
	int address_size,
	int data_size,
	bool word,
	bool dir,
	int override_seg )
{


	 comment_Ev(
		code, 
		 address_size,
		data_size,
		 word,
		 override_seg,
		 false );


	//len+= comment_Rv(
	//	(code[1]>>3)&7, 
	//	buffer+len,
	//	data_size,
	//	 word);


	return 0;
}
