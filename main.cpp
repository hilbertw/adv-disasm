// disasm.cpp : Defines the entry point for the console application.
//
#define _CRT_SECURE_NO_WARNINGS 1
#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "pe32.h"
#include "common.h"
#include "ifetcher.h"
#include "util.h"

#include "type-db.h"
#include "filemap.h"
#include "adv-disasm.h"

int do_guid_file(WCHAR* fname);
void dump_data();
void do_interactive();
//
//
// /pe32 <pe32 filename>
//
// /bin16 <bin file name>  offset bytes start seg
// /bin32 <bin file name>  offset bytes start seg

int _tmain(int argc, _TCHAR* argv[])
{
	
	if (argc<2)
		do_interactive();

	do_guid_file(argv[1]);

	return 0;
}

//
// check buffer size.
//
static int scan_string(char *src,WCHAR buffer[],int max_len)
{	
	char c,c1,*old_src=src;
	int len=0;


	if(src[0]=='"') {c1='"';src++;}
	else c1= ' ';

	
	//copy to '"'
	do
	{
		c=src[0];

		if (c==c1) break;
      	if (c< ' ') break;		
		if(len ==max_len) {len--;break;}
		buffer[len]=c;
		src++;
		len++;
	}while(1);

	buffer[len++]=0;
	//
	// "" is recognized as an argument
	//
	if( 1==len&&c1==' ') buffer[0]=0xffff;// no argument scanned.
	return src-old_src;
}

extern WCHAR command_arg_buffer[1024];

unsigned int exec_command( int argc, WCHAR *argv[]);


void do_interactive()
{
	char *prompt[]={"NO FILE","BIN16","BIN32","PE32"};

	while(1)
	{
		printf("\n%s>",prompt[disasm_mode]);

		int err_code=0;
		//
		// to interface with command executer
		//
		WCHAR * argv[5];
		int argc=0;
		int buffer_tail=0,pos=0;
		char src[1024];

		gets(src);
		if(_stricmp(src,"quit")==0) break;
		do
		{

		while(src[pos]==' '||src[pos]=='\t') pos++;

		unsigned int max_len=strlen(src);
		if( max_len >sizeof(command_arg_buffer)/sizeof(command_arg_buffer[0])-buffer_tail)
			max_len=sizeof(command_arg_buffer)/sizeof(command_arg_buffer[0])-buffer_tail;

		int len=scan_string(src+pos,command_arg_buffer+buffer_tail,max_len );

		//wprintf(L"%d %d %s\n",len,buffer_tail,command_arg_buffer+buffer_tail);
		if(command_arg_buffer[buffer_tail]==0xffff) break;
		if(!len) break;
		argv[argc++]=command_arg_buffer+buffer_tail;
		buffer_tail+=len+1;
		pos+=len;
		} while ( argc<sizeof(argv)/sizeof(argv[0]));


		exec_command(argc,argv);

	}

}
