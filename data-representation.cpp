#define _CRT_SECURE_NO_WARNINGS 1
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "util.h"
#include "filemap.h"
#include "guidinfo.h"
#include "adv-disasm.h"
extern  SLIST * data_list; // < addr, type,name>, static data
//
// print data in the following form:
//
// string  0000 name  db "example",0
// short   0000 name  dw 8888, 9999
// long    0000 name  dd 44444444,55555555
// wcstring 0000 name dw L"",0
// struct   0000 name
//          0002 field dw 1111
//
//

void print_data(char * buffer, unsigned long  va, char * _start,unsigned long  _size );
void print_struct(char * data,SLIST * p, unsigned int address);
void print_union(char * data,SLIST * p, unsigned int address);



void print_binary(char * buffer, unsigned long  va, char * _start,unsigned long  _size )
{
	unsigned long  i,len=0, start_pos,bytes_in_line;

	start_pos=va&0xf;
	va&= 0xfffffff0;

	for( i=0;i<(unsigned long )_size;i+=16 ){
		unsigned long  j,k;
		unsigned char  c;

		//
		// address
		//
		printf( "%08x ",va );

		//
		// 
		//
		for( j=0;j<start_pos;j++ ) printf( "   ");
			

		bytes_in_line=16-start_pos;
		
		//
		// index of last byte in line
		//
		k=i+bytes_in_line;

		if( k>(unsigned long )_size ) k=(unsigned long )_size;
		for( j=i;j<k;j++) {
			printf( "%02x ",((unsigned char *)_start)[j] );
		}
		
		for( ;j<(unsigned long )i+16 ;j++ ) printf( "   ");

		for( j=0;j<start_pos;j++ ) buffer[len++]=' ';
		for( j=i;j<k;j++) 
			printf( "%c",(c=((unsigned char *)_start)[j])<' '?'.':(c<0x80?c:'.') );
			
		printf( "\xd\xa" );
		//
		// next line
		//
		va +=16;
		start_pos=0;
	}
}



char scope_names[1024];


void print_data(char * data_ptr, PGENERAL_TYPE  type_info, int num, unsigned int address,char *name )
{
	int i;

	printf(real_mode()?"\n%04X %s%s ":"\n%08X %s%s ",address, scope_names,name);
l1:
	switch(type_info->type_code)
	{
	case T_CHAR:
	case T_UCHAR:
		//
		// 0000  00      name db 00
		printf ("db ");
		for(i=0;i<num;i++)
		printf("%02X ", (unsigned char )data_ptr[i]);
		printf ("; '");
		for(i=0;i<num;i++)
			printf("%c", (data_ptr[i]>=' '&&data_ptr[i]<=127)?data_ptr[i]:'.');
		printf ("'");
		break;
	case T_WCHAR:
		//
		// 0000  00      name db 00
		printf ("dw ");
		for(i=0;i<num;i++)
		printf("%04X ",((short *)data_ptr)[i]);
		printf ("; L\"");
		for(i=0;i<num;i++)
		{
			wchar_t c=((short *)data_ptr)[i];

			wprintf(L"%c", ((c>=L' '&&c<=127)||(c>255))?c:L'.');
		}
		printf ("\"");
		break;

	case T_SHORT:
	case T_USHORT:
		//
		// 0000  00      name db 00
		printf ("dw ");
		for(i=0;i<num;i++)
		printf("%04X ",((unsigned short *)data_ptr)[i]);

		break;
	case T_FLOAT:

		//
		// 0000  00      name db 00
		printf ("db ");
		for(i=0;i<num*(int)sizeof(float);i++)
		printf("%02X ", data_ptr[i]);
		printf ("; ");
		for(i=0;i<num;i++)
		printf("%f ", ((float *)data_ptr)[i]);
	
		break;
	case T_DOUBLE:
		//
		// 0000  00      name db 00
		printf ("db ");
		for(i=0;i<num*(int)sizeof(double);i++)
		printf("%02X ", data_ptr[i]);
		printf ("; ");
		for(i=0;i<num;i++)
		printf("%lf ", ((double *)data_ptr)[i]);

		break;
	case T_INT:
	case T_UINT:
	case T_LONG:
	case T_ULONG:
		//
		// 0000  00      name db 00
		printf ("dd ");
		for(i=0;i<num;i++)	
			printf("%08X ",((unsigned long *)data_ptr)[i]);

		break;
	case T_INT64:
	case T_UINT64:
		//
		// 0000  00      name db 00
		printf ("dq ");
		for(i=0;i<num;i++)
		{
		printf("%08X",((unsigned int *)data_ptr)[i+i+1]);
		printf("%08X ",((unsigned int *)data_ptr)[i+i]);
		}
		break;

	case T_STRING:
		//
		// 0000  00      name db 00
		printf ("db '");
		while (*data_ptr){ printf (data_ptr[0]<' '?"\\x%02x":"%c", data_ptr[0]);data_ptr++;}
		break;
	case T_WCSTRING:
		//
		// 0000  00      name db 00
		wprintf (L"db L\"%s\",0", data_ptr);
		break;
	case T_STRUCT:
		strcat(scope_names,name);
		strcat(scope_names,".");
		printf ("struct %s:\n",((PCOMPLEX_TYPE)type_info)->hdr.identifier );
		print_struct(data_ptr,((PCOMPLEX_TYPE)type_info)->member_list,address);
		printf ("\n");

		break;
	case T_UNION:
		printf ("union %s:\n",((PCOMPLEX_TYPE)type_info)->hdr.identifier );
		print_union(data_ptr,((PCOMPLEX_TYPE)type_info)->member_list,address);
		printf ("\n");
		break;
	case T_TYPEDEF:
		//
		// pointers
		//
		if(((PALIAS_TYPE)type_info)->pointer_level)
		{
			//
			// 0000  00      name db 00
			printf ("dd ");
			for(i=0;i<num;i++)	
				printf("%04X ",((long *)data_ptr)[i]);
			printf ("; pointer%c to %s",num?'s':' ',((PALIAS_TYPE)type_info)->type_info->identifier);
		}
		else
		{

				
				num=((PALIAS_TYPE)type_info)->num_elements*num;
				type_info=((PALIAS_TYPE)type_info)->type_info;
				goto l1;

	
		}
	default:
		printf("unimplemented.(%s)",type_info->identifier);
	}
}

void print_struct(char * data,SLIST * p, unsigned int address)
{
	while(p)
	{
		PMEMBERINFO member=(PMEMBERINFO)(p+1);
		
		print_data(data+member->byte_offset,
			member->decl.type_info,
			member->decl.num_elements,
			address+member->byte_offset,
			member->decl.identifier);


		p=p->next;
	}
}

void print_union(char * data,SLIST * p, unsigned int address)
{
	while(p)
	{
		PDECLARATOR member=(PDECLARATOR)(p+1);
		
		print_data(data,
			member->type_info,
			member->num_elements,
			address,
			member->identifier);


		p=p->next;
	}
}

extern char * data_base;
extern int dataseg_base;
extern unsigned int addr_base,dataseg_size;
bool pe32_map_data(unsigned int virtualAddress,unsigned int size);

void represent_data(PDATA_REC data_rec)
{
	char *data_ptr;
	int size=data_rec->num*data_rec->type_info->size;
	//
	// data's address  is out of range of the data seg? won't deal with 
	// a portion of data is available
	//
	if(data_rec->address+dataseg_base<addr_base ||
		data_rec->address+dataseg_base+size>addr_base+dataseg_size
		)
	{

		// in pe32 mode, remap the data section. if fail.
		if(!pe32_mode()||!(pe32_map_data(data_rec->address,size)) )
		{
			printf("%s - addr:%x,size:%d, out of range.\n",data_rec->name,data_rec->address,size);
			return;
		}
	}

	//
	// print adress, and memory dump
	//
		data_ptr=data_base+data_rec->address-addr_base+dataseg_base;

	scope_names[0]=0;
	print_data( data_ptr, 
		data_rec->type_info,
		data_rec->num,
		data_rec->address,
		data_rec->name);

    //
	// calc data size
	//
	//if(data_rec->type_info->type_code==T_STRING)
	//{
	//	size= strlen( data_ptr)+1;// includes null
	//}
	//else if(data_rec->type_info->type_code==T_WCSTRING)
	//{
	//	size= wcstrlen( data_ptr)+2;// includes null
	//}
	//else 
	//{
	//	size= data_rec->type_info->size*data_rec->num;
	//}
	//
	// dump data
	//

}