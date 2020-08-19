#define _CRT_SECURE_NO_WARNINGS 1
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "util.h"
#include "filemap.h"
#include "guidinfo.h"
#include   <assert.h>    
#include   <setjmp.h>     


void sys_error();

SLIST  data_list; // < addr, type,name>, static data
SLIST  procedure_list;//< addr, type> C functions/ asm proc
SLIST  comments_list;//< addr, char *> comments
SLIST  parameter_list;//< addr, char *> comments
SLIST  typehint_list;//< addr, char *> comments


PDATA_REC lookup_datarec( unsigned int addr)
{
	SLIST * p=data_list.next;

	while(p)
	{
		PDATA_REC p_data=(PDATA_REC)(p+1);

		if(p_data->address<=addr&&addr<p_data->address+p_data->type_info->size*p_data->num) return p_data;

		p=p->next;
	}
	return NULL;
}

PTYPE_REC lookup_type( unsigned int addr)
{
	SLIST * p=typehint_list.next;

	while(p)
	{
		PTYPE_REC p_data=(PTYPE_REC)(p+1);

		if(p_data->address==addr) return p_data;

		p=p->next;
	}
	return NULL;
}

PTEXT_REC lookup_commentrec( unsigned int addr)
{
	SLIST * p=comments_list.next;

	while(p)
	{
		PTEXT_REC p_data=(PTEXT_REC)(p+1);

		if(p_data->address==addr) return p_data;

		p=p->next;
	}
	return NULL;
}
PPROCEDURE_REC lookup_proc( unsigned int addr)
{
	SLIST * p=procedure_list.next;

	while(p)
	{
		PPROCEDURE_REC p_data=(PPROCEDURE_REC)(p+1);

		if(p_data->address==addr) return p_data;

		p=p->next;
	}
	return NULL;
}
PPARAMETER_REC lookup_parameter( unsigned int addr)
{
	SLIST * p=parameter_list.next;

	while(p)
	{
		PPARAMETER_REC p_data=(PPARAMETER_REC)(p+1);

		if(p_data->address==addr) return p_data;

		p=p->next;
	}
	return NULL;
}

char * lookup_enum(unsigned int address, unsigned int data)
{
	PTYPE_REC p=lookup_type(address);
	if(p&&p->type_info->type_code==T_ENUM)
			return get_enum_symbol( p->type_info,data);
	
	return NULL;
}

char * lookup_proc_name(unsigned int address)
{
	PPROCEDURE_REC p=lookup_proc(address);
	return p?p->name:NULL;
}

char * lookup_comments(unsigned int address)
{
	PTEXT_REC p=lookup_commentrec(address);
	return p?p->text:NULL;
}
char * lookup_data(unsigned int address)
{
	PDATA_REC p=lookup_datarec(address);

	if(p->type_info->type_code==T_STRUCT)
	{
		return get_struct_field_symbol( p->type_info,address-p->address);
	}
	return p?p->name:NULL;
}


PMEMBERINFO get_struct_field( PGENERAL_TYPE type_info, unsigned int offset );

int print_data_name( char *buffer,unsigned int address)
{

	PDATA_REC p=lookup_datarec(address);
	if(!p) return 0;

	assert(address>=p->address);

	unsigned int disp=address-p->address;
	int len;
	len=sprintf( buffer,"%s",p->name);

	 PGENERAL_TYPE type_info=p->type_info;
l1:
	 while(type_info->type_code==T_TYPEDEF)
		type_info=((PALIAS_TYPE)type_info)->type_info;
	
	while (type_info->type_code==T_STRUCT)
	{
		PMEMBERINFO pmember=get_struct_field( type_info,disp);
		if(!pmember) goto out;
		len+=sprintf( buffer+len,".%s",pmember->decl.identifier);

		disp-=pmember->byte_offset;
		type_info=pmember->decl.type_info;
		goto l1;
	}
out:
	return len;
}

int print_struct_name( char *buffer,unsigned int address,unsigned int  disp)
{

	PTYPE_REC p=lookup_type(address);
	if(!p) return 0;

	assert(address>=p->address);

	int len=0;
	//len=sprintf( buffer,"%s",p->type_info->identifier);

	 PGENERAL_TYPE type_info=p->type_info;
l1:
	 while(type_info->type_code==T_TYPEDEF)
		type_info=((PALIAS_TYPE)type_info)->type_info;
	
	while (type_info->type_code==T_STRUCT)
	{
		PMEMBERINFO p_member=get_struct_field( type_info,disp);
		if(!p_member) goto out;

		disp-=p_member->byte_offset;
		type_info=p_member->decl.type_info;
		if(!p_member->decl.num_elements)
		{
		len+=sprintf( buffer+len,".%s",p_member->decl.identifier);
		}
		else
		{
			int element_size=p_member->decl.pointer_level?4:p_member->decl.type_info->size;
			int size=p_member->decl.num_elements*element_size;
			len+=sprintf( buffer+len,".%s[%d]",p_member->decl.identifier,disp/element_size);
		}


		goto l1;
	}
out:
	return len;
}

char * lookup_struct(unsigned int address, unsigned int disp)
{
	PTYPE_REC p=lookup_type(address);
	if(p)
	{
		if(p->type_info->type_code==T_STRUCT)
		{
			return get_struct_field_symbol( p->type_info,disp);
		}
		else if(p->type_info->type_code==T_UNION)
		{
			return get_union_member_symbol( p->type_info,disp);
		}
	}
	return NULL;
}

void add_comments( unsigned int address, char * comments)
{
		SLIST * p=add_node(&comments_list, sizeof(TEXT_REC));

		if (!p)sys_error();

		((PTEXT_REC)(p+1))->address=address;
		((PTEXT_REC)(p+1))->text=comments;
				//printf("%x comments:%s\n",address,comments);
}
void add_parameter( unsigned int address, char reg_no,char * comments)
{
	//
	// lookup the proc record
	//
	PPROCEDURE_REC proc=lookup_proc(address);
	if(!proc)
	{
		printf("warning:there is not a procedure @ address (%x).parameter omitted.\n",address);
		return;
	}

	SLIST * p=add_node(&proc->parameter_list, sizeof(PARAMETER_REC));

		if (!p)sys_error();

		((PPARAMETER_REC)(p+1))->address=address;
		((PPARAMETER_REC)(p+1))->text=comments;
		((PPARAMETER_REC)(p+1))->reg_no=reg_no;

				//printf("%x para:%s\n",address,comments);
}

void add_procedure( unsigned int address, char * name,char type)
{
		SLIST * p=add_node(&procedure_list, sizeof(PROCEDURE_REC));

		if (!p)sys_error();

		((PPROCEDURE_REC)(p+1))->address=address;
		((PPROCEDURE_REC)(p+1))->name=name;
		((PPROCEDURE_REC)(p+1))->type=type;
		((PPROCEDURE_REC)(p+1))->parameter_list.next=NULL;

		//printf("%x proc:%s\n",address,name);
}

void add_data( unsigned int address, char * name,PGENERAL_TYPE type, int num)
{
		SLIST * p=add_node(&data_list, sizeof(DATA_REC));

		if (!p)sys_error();

		((PDATA_REC)(p+1))->address=address;
		((PDATA_REC)(p+1))->name=name;
		((PDATA_REC)(p+1))->type_info=type;
		((PDATA_REC)(p+1))->num=num;
		//printf("%x data:%s\n",address,name);
}

void add_type( unsigned int address, PGENERAL_TYPE type)
{
		SLIST * p=add_node(&typehint_list, sizeof(TYPE_REC));

		if (!p)sys_error();

		((PTYPE_REC)(p+1))->address=address;
		((PTYPE_REC)(p+1))->type_info=type;

		//printf("%x type:%s\n",address,type->identifier);
}
//
// add a var 
//

bool add_var(unsigned int address_of_proc,int off,char *name,int name_len,PGENERAL_TYPE type_info,int num)
{
	//
	// lookup the proc record
	//
	PPROCEDURE_REC proc=lookup_proc(address_of_proc);
	if(!proc||proc->type!=PROC_TYPE_CFUNCTION)
	{
		//printf("warning:there is not a procedure @ address (%x).parameter omitted.\n",address);
		return false;
	}

	SLIST * p=add_node(&proc->var_list, sizeof(VAR_REC)+name_len+1);

		if (!p) return false;

		((PVAR_REC)(p+1))->byte_offset=off;
		((PVAR_REC)(p+1))->decl.identifier=(char *)( (PVAR_REC)(p+1)+1 );
		((PVAR_REC)(p+1))->decl.type_info=type_info;
		((PVAR_REC)(p+1))->decl.num_elements=num;
		((PVAR_REC)(p+1))->decl.pointer_level=0; // not support pointer now.
		strncpy(((PVAR_REC)(p+1))->decl.identifier,name,name_len);// copy string to its end
		((PVAR_REC)(p+1))->decl.identifier[name_len]=0; // mark end by null

				//printf("%x para:%s\n",address,comments);
		return true;
}
void  order_data()
{
	SLIST *q=NULL,*r=NULL,*p,*s=data_list.next;

	while(p=s)
	{
		// detach from data_list
		s=s->next;

		PDATA_REC rec=(PDATA_REC)(p+1);
		unsigned long addr=rec->address;
		//
		//  add to q
		//
		r=q;
		
		if(NULL==q) {q=p;p->next=NULL;continue;}
		if(addr<((PDATA_REC)(q+1))->address)
		{
			p->next=q;
			q=p;
			continue;
		}
		while(r->next)
		{	
				rec=(PDATA_REC)(r+1);
				PDATA_REC rec1=(PDATA_REC)(r->next+1);
			
				if(addr>rec->address&&addr<=rec1->address) break;	
				r=r->next;
		}
		p->next=r->next;
		r->next=p;
	}

	data_list.next=q;
}
void represent_data(PDATA_REC data_rec);

void dump_data()
{

	order_data();
	SLIST * p=data_list.next;

	while(p)
	{
		PDATA_REC rec=(PDATA_REC)(p+1);
		represent_data(rec);

		p=p->next;
	}
}




char * guid_info_reg_name[]=
{
"AL",    "CL",    "DL",    "BL",    "AH",    "CH",    "DH",    "BH",
"AX",    "CX",    "DX",    "BX",   "SP",    "BP",    "SI",    "DI",
"EAX",    "ECX",  "EDX",    "EBX",  "ESP",   "EBP",   "ESI",   "EDI",
"ES",     "CS",   "SS",     "DS",   "FS",    "GS"
};


//
// return the index of the register name, return -1 on error
//
char get_regno(char * name, int len)
{

	int i;

	for(i=0;i<sizeof(guid_info_reg_name)/sizeof(guid_info_reg_name[0]);i++)
		if(len==strlen(guid_info_reg_name[i])&&
			!_strnicmp(name,guid_info_reg_name[i],len)) return i;

	return -1;
}

void print_proc_info(unsigned int address)
{
	extern FILE *  fp_output;
	PPROCEDURE_REC proc=lookup_proc(address);
	if(proc)
	{
		fprintf(fp_output,"%s proc\n",proc->name);

		if(proc->type==PROC_TYPE_ASMPROC)
		{
			SLIST * p=proc->parameter_list.next;
			while(p)
			{
				PPARAMETER_REC q=(PPARAMETER_REC)(p+1);
				fprintf(fp_output,"\t%s -- %s\n",guid_info_reg_name[q->reg_no],q->text);

				p=p->next;
			}
		}
		else
		{
			SLIST * p=proc->var_list.next;
		while(p)
		{
			PVAR_REC q=(PVAR_REC)(p+1);
			fprintf(fp_output,"\t-%04x -- %s %s\n",q->byte_offset,q->decl.type_info->identifier,q->decl.identifier);

			p=p->next;
		}
		}
	}
}
