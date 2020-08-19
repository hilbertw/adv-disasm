#include "stdlib.h"
#include "string.h"
#include "util.h"
#include "filemap.h"
#include "guidinfo.h"
#include   <stdio.h>  
#include   <setjmp.h>  


extern PGENERAL_TYPE basic_type_info[];
//
// data shared from api-db.cpp
//
const  PGENERAL_TYPE type_char = basic_type_info[T_CHAR];
const  PGENERAL_TYPE type_wchar = basic_type_info[T_WCHAR];
const  PGENERAL_TYPE type_short = basic_type_info[T_SHORT];
const  PGENERAL_TYPE type_int = basic_type_info[T_USHORT];
const  PGENERAL_TYPE type_int64 = basic_type_info[T_INT64];

GENERAL_TYPE type_string={T_STRING,NULL,0};
GENERAL_TYPE type_wcstring={T_WCSTRING,NULL,0};
//
// protected data/
//
static  jmp_buf   jumper; 
static  CFileMapEx file_map;
static  unsigned int pos,row;
static unsigned int line_pos; // to help tracking col

wchar_t * err_msg[]={
	L"unrecognized command. ignored",//1
	L"bad file name", //2
	L"bad address",//3
	L"bad parameter for command",//4
	L"address expected",//5
	L"unrecognized instruction",//6
	L"undefined type",//7
	L"bad integer",//8
	L"']' is missing",//9
	L"unknown register",//10
	L"command line too long",//11
	L"unknown command",//12
	L"too few arguments incommand line ",//13
	L"can not open file",//14
	L"use pe32,bin15 or bin32 before disasm",//15
	L"bad address",//16
	L"bad hexical number",//17
	L"can not add var, not a proc or out of memory"//18
};

static void skip_space()
{
	char c;

	while((c=file_map[pos])<=' '&&c!=10) 	pos++;
}

static void skip_empty_line()
{
	char c;

	while((c=file_map[pos])<=' ') 
	{
		pos++;
		if(c==10)  { row++;line_pos=pos;}
	}

}
//
//return length of  the next word
//
static int scan_word()
{
	int len=0;
	
	skip_space();


    for(;;) 
	{		char c;
		 c=file_map[pos+len];
		 
	     if (c=='_'||(c>='0'&&c<='9')||(c>='a'&&c<='z')||(c>='A'&&c<='Z')) len++; 
		 else break;
	}


	return len;
}
//
//return length to eol
//
static int scan_comments()
{
	int len=0,len1=0;

	
    for(;;) 
	{	
		char c;

		 c=file_map[pos+len];
		 
		 if (c==10||c==0x7f)  break;

		 len++;  
		 if ( c>' ') len1=len;
		 
	}

	return len1;
}


int scan_decimal(int *ret_value)
{
	int num=0;
	unsigned int old_pos;
	
	skip_space();

	old_pos=pos;
    while(pos< file_map.max_pos) 
	{		
		char c;
		c=file_map[pos];
		

		 if ((c>='0'&&c<='9')) { num=num*10+c-'0'; pos++;}
		 else 
			 break;
	}

	*ret_value=num;
	return pos>old_pos;
}

int scan_hex(int *ret_value)
{
	int num=0,digit;
	unsigned int old_pos;
	
	skip_space();

	
    for(old_pos=pos;pos< file_map.max_pos;pos++) 
	{		
		char c;
		c=file_map[pos];
		

		 if ((c>='0'&&c<='9')) { digit=c-'0'; }
		 else if ((c>='a'&&c<='f')) { digit=c-'a'+10; }
		 else if ((c>='A'&&c<='F')) { digit=c-'A'+10; }
		 else 
			 break;
		
		num=num*16+digit;
	}

	*ret_value=num;
	return pos>old_pos;
}

PGENERAL_TYPE  get_type(char *name,int len)
{
	PGENERAL_TYPE type=NULL;


	//unsigned int i;
	//for(i=0;i<len;i++) printf("%c",file_map[pos+i]);
	//printf("\n");
	if(len==4&& !strncmp(name,"char",4))
	{
		type=type_char;
	}
	else 	if(len==7&& !strncmp(name,"wchar_t",7))
	{
		type=type_wchar;
	}
	else 	if(len==5&& !strncmp(name,"short",5))
	{
		type=type_short;
	}
	else  	if(len==4&& !strncmp(name,"long",4))
	{
		type=type_int;
	}
	else  	if(len==6&& !strncmp(name,"string",6))
	{
		type=&type_string;
	}
	else   	if(len==8&& !strncmp(name,"wcstring",8))
	{
		type=&type_wcstring;
	}
	else
		type=lookup_typedef(name,len);

	return type;
}
char * put_string(char *src, unsigned int bytes);

int def_var(int address_of_proc)
{
	int err_code=0;
	//
	// expcting a hex
	//
	int off;
	int len=scan_hex(&off);
	pos+=len;

	if(0==len||0==off)
	{
		err_code=17; // bad hex
		goto out;
	}


	skip_space();
	//
	// expcting a type
	//
	len=scan_word();

	PGENERAL_TYPE  type=get_type((char *)file_map+pos,len);
	pos+=len;
	if(0==type)
	{
		err_code=2; // undefined type
		goto out;
	}
	skip_space();
	//
	// expcting a name, copy later.so remember pos and len
	//
	int pos_name=pos;  
	int len_name=scan_word();
	pos+=len_name;




	skip_space();

	//
	// process array definition
	//
	int num=1;
	if(file_map[pos]=='[')
	{
			pos++;
			//
			// expecting a decimal num
			//
			if(0==scan_decimal(&num)||0==num)
			{
				err_code=8; // bad integer
				goto out;
			}
			skip_space();
			if(file_map[pos]!=']')
			{
				err_code=9;//missing ']'
				goto out;
			}
			pos++;
	}
	//
	// now to add var
	//
	char * name=(char *)file_map+pos_name;
	if(!add_var(address_of_proc, off,name,len_name,type,num))
		err_code=18;
out:
	return err_code;
}





static int scan_line()
{
//
// ip address for each line. don't put it as auto. it may be reused in 
// the next line  if address  is omitted in the next lines, 
//
	static unsigned int address;
	PGENERAL_TYPE type;
	unsigned int line_pos,len;
	char * name;
	char procedure_type;
	int err_code=0;
	
	line_pos=pos;
	//
	// adresss
	//

	if (file_map[pos]=='+') pos++;
	else {
		len=htoi((char*)file_map+pos, ' ',8, address);

		if (!len)
		{
			err_code=5; // error: 
		//printf("guid file:adress expected.row:%d,col:%d\n",row,pos-line_pos);
			goto out;
		}
		pos+=len;
	}
	//
	// type/proc/para/
	//
	skip_space();
	//
	// -- comments
	//
	if( !strncmp((char*)file_map+pos,"--",2))
	{
		char * comments;
		pos+=2;

		len=scan_comments();
		if (!len) goto out; // skip empty comments
		//
		//  save comments
		//
		comments=put_string((char *)file_map+pos,len);
		//
		// addcomments
		//
		add_comments(address,comments);
		pos+=len;
		goto out;

	}
	len=scan_word();
if(len==4&& !strncmp((char*)file_map+pos,"proc",4))
	{
		procedure_type=PROC_TYPE_ASMPROC;
		goto def_proc;
	}
	else  	if(len==8&& !strncmp((char*)file_map+pos,"function",8))
	{
		procedure_type=PROC_TYPE_CFUNCTION;
		goto def_proc;
	}
	else  	if(len==4&& !strncmp((char*)file_map+pos,"para",4))
	{
		goto def_parameter;
	}	 
	else   	if(len==3&& !strncmp((char*)file_map+pos,"var",3))
	{
		pos+=len;
		err_code=def_var(address);
		goto out;
	}	 
	else 	if(len==4&& !strncmp((char*)file_map+pos,"type",4))
	{
		pos+=len;
		//
		// expcting a name
		//
		skip_space();
		len=scan_word();
		type=get_type((char*)file_map+pos,len);

		 if(type)  add_type(address,type);
		 else err_code=7;// undefined type 

		 goto out0;
	}	 
	else  if(type=get_type((char*)file_map+pos,len))
	{
		goto def_data;
	}
	else
	{

		//
		// suppose a c type name  here, lookup typehint_list
		//
		err_code=6; // key word expected.
		goto out;
	}
def_data:
	pos+=len;

	//
	// expcting a name
	//
	len=scan_word();

	name=put_string((char *)file_map+pos,len);
	pos+=len;

	skip_space();

	//
	// process array definition
	//
	int num=1;
	if(file_map[pos]=='[')
	{
			pos++;
			//
			// expecting a decimal num
			//
			if(0==scan_decimal(&num)||0==num)
			{
				err_code=8; // bad integer
				goto out;
			}
			skip_space();
			if(file_map[pos]!=']')
			{
				err_code=9;//missing ']'
				goto out;
			}
			pos++;
	}

	add_data(address,name,type,num);
	goto out;

def_proc:
	pos+=len;
	//
	// expecting a name
	//
	len=scan_word();

	name=put_string((char *)file_map+pos,len);

	add_procedure(address,name,procedure_type);

	goto out0;
def_parameter:
	pos+=len;
	//
	// expecting a register name
	//
	len=scan_word();
	int reg_no=get_regno((char *)file_map+pos,len);

	if(reg_no<0)
	{
		err_code=10;//bad register
		goto out0;
	}
	//
	// -- comments
	//
	pos+=len;
	skip_space();

	if( !strncmp((char*)file_map+pos,"--",2))
	{
		char * comments;
		pos+=2;

		len=scan_comments();
		if(!len) goto out; // skip empty comments
		//
		//  save comments
		//
		comments=put_string((char *)file_map+pos,len);
		//
		// addcomments
		//
		add_parameter(address,reg_no,comments);
	
		goto out0;

	}

out0:
	pos+=len;
out:;
	return err_code;
}
//
// check buffer size.
//
int scan_string(WCHAR buffer[],int max_len)
{	
	char c,c1;
	int len=0;

	skip_space();

	if(file_map[pos]=='"') {c1='"';pos++;}
	else c1= ' ';

	
	//copy to '"'
	do
	{
		c=file_map[pos];

		if (c==c1) break;
      	if (c< ' ') break;		
		if(len ==max_len) {len=-1;break;}
		buffer[len]=c;
		pos++;
		len++;
	}while(pos < file_map.max_pos);

	buffer[len++]=0;
	//
	// "" is recognized as an argument
	//
	if( 1==len&&c1==' ') len=0;// no argument scanned.
	return len;
}

WCHAR command_arg_buffer[1024];

unsigned int exec_command( int argc, WCHAR *argv[]);

int scan_command() // see command.cpp
{
	int err_code=0;
	//
	// to interface with command executer
	//
	WCHAR * argv[5];
	int argc=0;
	int buffer_tail=0;

	do
	{
	int len=scan_string(command_arg_buffer+buffer_tail, sizeof(command_arg_buffer)/sizeof(command_arg_buffer[0])-buffer_tail);
	//wprintf(L"%d %d %s\n",len,buffer_tail,buffer+buffer_tail);
	if(len<0) {err_code=11; goto out;}
	if(!len) break;
	argv[argc++]=command_arg_buffer+buffer_tail;
	buffer_tail+=len;
	} while ( argc<sizeof(argv)/sizeof(argv[0]));

	err_code=exec_command(argc,argv);
	err_code=(err_code==0)?0:err_code+11;  // mapping error code if non 0 returned.
out:
	return err_code;
}
//
// scan guidance   file
// return  0: success, or error code
//
int do_guid_file(LPWSTR fname)
{
	int err;
	
	if(err=file_map.load_file(fname))
	{
		return err;
	}
    int value   =   setjmp(jumper);   
	//
	// can not continue on system error
	//
	if(value==3)  goto out;
	else if (value!=0) goto recover_from_error;
	

	
	//
	// declarations:: declaration declarations
	//
	while (1)
	{
		int err_code;
	skip_empty_line(); // scan LF, and update row
	
	if(file_map.eof(pos)) break;


	if(file_map[pos]=='.')
	{
		pos++; //drop '.'
		err_code=scan_command();
	}
	else
		err_code=scan_line();


	if(err_code)
		wprintf(L"%s  row:%d,col:%d:%s\n",fname,row,pos-line_pos,err_msg[err_code-1]);

recover_from_error:
	//
	// go to next line.
	//
	
	while(file_map[pos]!=10&&pos <file_map.max_pos)	pos++;

	}
out:
	// success. 
	file_map.close();

	return 0;
}