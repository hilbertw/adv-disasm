#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include "stdafx.h"
#include "pe32.h"
#include "common.h"
#include "ifetcher.h"
#include "util.h"
#include <sys/stat.h>
#include "type-db.h"
#include "filemap.h"
#include "adv-disasm.h"
static  CIFetcherMemory fetcher;
static  CFileMapEx file_map;
char * data_base;
unsigned int addr_base,dataseg_size;
int dataseg_base;

bool disasm_func(CIFetcherMemory fetcher, unsigned int addr);
int bin_open(bool bit16_mode,WCHAR* fname,unsigned int start)
{
	wprintf(L"Loading bin %s in  %d bit mode\n",fname,bit16_mode?16:32);
	if(file_map.load_file(fname))
	{
		return 1;
	}


	data_base=(char *)file_map;
	addr_base=start;
	dataseg_base=start;
	dataseg_size=file_map.size();

	fetcher.set_buffer((unsigned char *)data_base,file_map.size(),start);
	return 0;
}


int bin16_disasm_by_address(unsigned int  ip,unsigned short seg)
{
	//extern FILE *fp_output;

	//char buffer[MAX_PATH];
	//sprintf(buffer,"%04x-%04x.asm",seg,ip);

	//fp_output=fopen(buffer,"wt");
	//if(!fp_output)
	//{
	//	fprintf(fp_output,"can not write to file:%s\n",buffer);
	//}
	//else
	//{
		disasm_func( fetcher,real_mode()?((ip&0xffff)+(seg<<16)):ip);
	//	fclose(fp_output);
	//}
	return 1;
}
int bin32_disasm_by_address(unsigned int  ip)
{
	extern FILE *fp_output;

	char buffer[MAX_PATH];
	sprintf(buffer,"%08x.asm",ip);

	fp_output=fopen(buffer,"wt");
	if(!fp_output)
	{
		fprintf(fp_output,"can not write to file:%s\n",buffer);
	}
	else
	{
		disasm_func( fetcher,ip);
		fclose(fp_output);
	}
	return 1;
}
CExeFormatPE32 pe32;

int pe32_open(LPCTSTR fname)
{
	wprintf(L"Loading pe32:%s\n",fname);
	if (pe32.Open(fname))
		return 1;

	//
	//map data section?
	//
	dataseg_size=0;
	addr_base=0;
	dataseg_base=0;
	return 0;
}
int  check_pe32_address(unsigned int virtualAddress)
{
	PIMAGE_SECTION_HEADER    section;
	
	section=pe32.GetSectionPtr( virtualAddress);
	if( !section ) return 2;       // bad data

	unsigned char * data=(unsigned char * )pe32.MapSection(section);

	fetcher.set_buffer(data,section->SizeOfRawData,section->VirtualAddress);
	return 0;
}

void do_pe32_disasm_by_address(unsigned int virtualAddress)
{
	PIMAGE_SECTION_HEADER    section;
	
	section=pe32.GetSectionPtr( virtualAddress);
	if( !section ) return ;       // bad data

	unsigned char * data=(unsigned char * )pe32.MapSection(section);

	fetcher.set_buffer(data,section->SizeOfRawData,section->VirtualAddress);
	
	disasm_func( fetcher,virtualAddress);

	return ;
}


int pe32_disasm_by_address(unsigned int virtualAddress)
{
	extern FILE *fp_output;

	char buffer[MAX_PATH];
	printf("Disasm:%x:\n", virtualAddress);
	sprintf(buffer,"%08x.asm",virtualAddress);

	fp_output=fopen(buffer,"wt");
	if(!fp_output)
	{
		fprintf(fp_output,"can not write to file:%s\n",buffer);
	}
	else
	{
		 do_pe32_disasm_by_address(virtualAddress);
		fclose(fp_output);
	}
	return 0;
}

int pe32_disasm_by_name(wchar_t * name)
{
	unsigned long virtualAddress;
	if(NULL==name)
	{
	virtualAddress=pe32.EntryPoint();
	return pe32_disasm_by_address(virtualAddress);
	}
	
	else
	virtualAddress=pe32.GetRVAofExportedName(name);

	extern FILE *fp_output;

	wchar_t buffer[MAX_PATH];
	wsprintf(buffer,L"%s.asm",name);

	fp_output=_wfopen(buffer,L"wt");
	if(!fp_output)
	{
		printf("can not write to file:%s\n",buffer);
	}
	else
	{

		 do_pe32_disasm_by_address(virtualAddress);
		fclose(fp_output);
	}
	return 0;
}
//
// whether a function is a stub to a inported function thunk
//

char * pe32_check_imported_function_call(unsigned char *code)
{
	// call  far ptr?
	char*s=NULL;
	if(code[0]==0xff&&code[1]==0x15)
	{
		unsigned int addr = *(unsigned int*)(code+2);
		int ordinal;
		s=pe32.GetImportedNameByThunkRVA(addr,&ordinal);
		//printf (" calling:%s\n",s);
	}

	return s;
}

bool  check_pe32_thunk(unsigned int virtualAddress)
{
	PIMAGE_SECTION_HEADER    section;
	
	section=pe32.GetSectionPtr( virtualAddress);
	if( !section ) return false;   // bad data

	unsigned char * data=(unsigned char * )pe32.MapSection(section);

	data+=virtualAddress-section->VirtualAddress;
	return  pe32_check_imported_function_call(data)!=NULL;
}
void bin16_dump_data(unsigned int off,unsigned short seg,unsigned int size)
{
	unsigned int address=(off&0xffff)+(seg<<4);
	unsigned int max_addr=addr_base+file_map.size();
	if(max_addr<address) return;

	char *	s=data_base+address-addr_base+dataseg_base;
	unsigned int max_size=max_addr-address;

	if(size >max_size) size=max_size;
	print_mem16(s,seg,off,size);
}

void bin32_dump_data(unsigned int address,unsigned int size)
{
	char *s=data_base+address-dataseg_base;
	unsigned int max_addr=addr_base+file_map.size();
	if(max_addr<address) return;


	unsigned int max_size=max_addr-address;
	if(size >max_size) size=max_size;
	
	print_mem32(s,address,size);
}

//
// if data is acrossing pe 32 sections, don't care about it.
//
bool pe32_map_data(unsigned int virtualAddress,unsigned int size)
{
	PIMAGE_SECTION_HEADER    section;
	
	virtualAddress+=dataseg_base;

	section=pe32.GetSectionPtr( virtualAddress);
	if( !section ) return false;   // bad data
	
	data_base=( char * )pe32.MapSection(section);
	
	// virtualAddressmust be greater than section->VirtualAddress
	unsigned int off=virtualAddress-section->VirtualAddress;
	dataseg_size=section->SizeOfRawData;
	addr_base=section->VirtualAddress;
	return dataseg_size>=(off+size);
}

void pe32_dump_data(unsigned int virtualAddress,unsigned int size)
{
	char *data;
	//
	// data's address  is out of range of the data seg? won't deal with 
	// a portion of data is available
	//
	if(virtualAddress+size<addr_base ||
		virtualAddress+size>addr_base+dataseg_size||
		virtualAddress+size>addr_base+dataseg_size
		)
	{

		// in pe32 mode, remap the data section. if fail.
		if(!(pe32_map_data(virtualAddress,size)) )
		{
			printf("addr:%x,size:%d, out of range.\n",virtualAddress,size);
			return;
		}
	}

	data=data_base+virtualAddress-addr_base+dataseg_base;
	print_mem32(data,virtualAddress,size);

}

int pe32_get_max_strlen(unsigned int virtualAddress)
{
	int i=0;
	PIMAGE_SECTION_HEADER    section;
	
	virtualAddress+=dataseg_base;

	section=pe32.GetSectionPtr( virtualAddress);
	if( !section ) return 0;   // bad data
	
	data_base=( char * )pe32.MapSection(section);
	
	// virtualAddressmust be greater than section->VirtualAddress
	unsigned int off=virtualAddress-section->VirtualAddress;
	dataseg_size=section->SizeOfRawData;
	addr_base=section->VirtualAddress;

	return dataseg_size-off;
}


char * pe32_lookup_exported_func(unsigned long  address)
{
	int ordinal;
	char buffer[200];
	char *name=pe32.GetExportedNameByRVA(address,& ordinal);

	if(NULL==name && ordinal!=-1)
		name=put_string(buffer,sprintf(buffer,"%d",ordinal));
	
	return name;
}