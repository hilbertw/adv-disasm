#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include "stdafx.h"
#include "pe32.h"
#include "common.h"
#include "ifetcher.h"
#include "type-db.h"
#include "filemap.h"
#include "adv-disasm.h"
#include "util.h"
int do_include(LPCTSTR fname);
int do_pe32(LPCTSTR fname);
int do_bin32(LPCTSTR fname,unsigned long address);
int do_bin16(LPCTSTR fname,unsigned long seg, unsigned long offset);
int do_dumpdata( char * option, int len);
int do_disasm( char * option, int len);
int scan_header_file(LPCTSTR fname);
bool disasm_func(CIFetcherMemory fetcher, unsigned int addr);
int disasm_bin(bool bit16_mode,WCHAR* fname,unsigned int start,unsigned int ip,unsigned short seg=0);
int disasm_pe32(LPCTSTR fname);
void bin32_dump_data(unsigned int address,unsigned int size);
void pe32_dump_data(unsigned int address,unsigned int size);
void bin16_dump_data(unsigned int off,unsigned short seg,unsigned int size);
void dump_data();
int bin_open(bool bit16_mode,WCHAR* fname,unsigned int start);

int bin16_disasm_by_address(unsigned int  ip,unsigned short seg);
int bin32_disasm_by_address(unsigned int  ip);
int pe32_open(LPCTSTR fname);
int pe32_disasm_by_address(unsigned int  ip);
int pe32_disasm_by_name(wchar_t * name);


 DISASM_MODE disasm_mode;

unsigned int exec_command( int argc, WCHAR *argv[])
{
	int err_code=0;
	static unsigned short bin16_seg;

	if (!_wcsicmp(argv[0],L"pe32"))
	{
		
		if(! pe32_open(argv[1]))
		{
			disasm_mode=PE32;
		}
		else
		{
			err_code=3;
			goto err;
		}

	}else if (!_wcsicmp(argv[0],L"bin16"))
	{
		unsigned int  ip,seg;

		int l;
		if(argc<3) {err_code=2; goto err;}
		if(!(l=convert_hex(argv[2],L':',4,seg))) goto hex_err;
		if(!convert_hex(argv[2]+l,L'\0',4,ip)) goto hex_err;

		
		bin16_seg=seg;
		if(! bin_open(true,argv[1],bin16_seg*16+ip))
		{
			disasm_mode=BIN16;
		}else
		{
			err_code=3;
			goto err;
		}
	}
	else if (!_wcsicmp(argv[0],L"bin32"))	
	{
		unsigned int off;
		if(argc<3) {err_code=2; goto err;}
		if(!convert_hex(argv[2],L'\0',8,off)) goto hex_err;

		if(! bin_open(false,argv[1],off))	disasm_mode=BIN32;
		else
		{
			err_code=3;
			goto err;
		}
	}else if (!_wcsicmp(argv[0],L"include"))	
	{
		if(argc<2) {err_code=2; goto err;}

		int i=scan_header_file((LPCTSTR)argv[1]);
		if(i==-1) {err_code=3; goto err;}
		if(i) wprintf(i==-2?L"%s compiled with too many errors or warnings\n":
			L"%s compiled with %d errors and %d warnings\n",
			argv[1],i>>16,i&0xffff);
	}
	else if (!_wcsicmp(argv[0],L"add"))	  // add a function  to the task list
	{
		unsigned int ip,seg;
		switch(disasm_mode)
		{
			case BIN16: 

				if(argc<2) {err_code=2; goto err;}
				if(wcschr(argv[1],L':'))
				{
					int l;
					if(!(l=convert_hex(argv[1],L':',4,seg))) goto hex_err;
					if(!convert_hex(argv[1]+l,L'\0',4,ip)) goto hex_err;

				}
				else 
				{
					if(!convert_hex(argv[1],L'\0',8,ip)) goto hex_err;
					seg=bin16_seg; // use default
				}
				printf("add:%x:%x\n",seg,ip);
				bin16_disasm_by_address(ip,seg);
				break;
			case BIN32: 
				if(argc<2) {err_code=2; goto err;}
				if(!convert_hex(argv[1],L'\0',8,ip)) {
hex_err:
				err_code=5;
				}
				else
				{
				bin32_disasm_by_address(ip);
				}
				break;
			case PE32:
				if(argc<2) {pe32_disasm_by_name(NULL);}
				else
				if(convert_hex(argv[1],L'\0',8,ip)) 
				{
					pe32_disasm_by_address(ip);
				}
				else
					pe32_disasm_by_name(argv[1]);

				break;
			default:
				{err_code=4; goto err;}
		}
	}
	else if (!_wcsicmp(argv[0],L"dump"))	
	{
		void dump_types();

		if(argc==2&& !_wcsicmp(argv[1],L"types")) {dump_types();goto err;}
		if(argc==3&& !_wcsicmp(argv[1],L"type")) {
			PGENERAL_TYPE lookup_typedef2(wchar_t *identifier);
			void dump_type(PGENERAL_TYPE decl);

			PGENERAL_TYPE p= lookup_typedef2(argv[2]);
			if(p) dump_type(p);else wprintf(L"%s Not found.\n",argv[2]);
			goto err;
		}
		unsigned int address,size;
		if(argc<3) {err_code=2; goto err;}
		if(!convert_hex(argv[1],L'\0',8,address)) goto hex_err;
		if(!convert_hex(argv[2],L'\0',8,size)) goto hex_err;

		switch(disasm_mode)
		{
			case BIN16:
				bin16_dump_data(address,bin16_seg,size);
				break;
			case BIN32:
				bin32_dump_data(address,size);
				break;
			case PE32:
				pe32_dump_data(address,size);
				break;
		}
	}	
	else if (!_wcsicmp(argv[0],L"base"))	
	{
		extern int dataseg_base;
		unsigned int address;
		bool sign;
		if(argc<2) {err_code=2; goto err;}

		wchar_t *s=argv[1];
		if(s[0]=='-') { sign=false; s++;} else sign=true;
		if(s[0]=='+') {  s++;}
		if(!convert_hex(s,L'\0',8,address)) goto hex_err;
		dataseg_base=(sign)?(signed)address:-(signed)address;
	}
	else if (!_wcsicmp(argv[0],L"printdata"))	
	{
		if(disasm_mode!=UNKNOWN)
		dump_data();
	
	}
	else if (!_wcsicmp(argv[0],L"output"))	
	{
		if(disasm_mode!=UNKNOWN)
		dump_data();
		void do_disasm ();
		 do_disasm ();
	
	}
	else
		err_code=1; // unknown command

err:

	return err_code;
}
