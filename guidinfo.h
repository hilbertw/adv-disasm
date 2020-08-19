#ifndef __guidinfo_h__
#define __guidinfo_h__
#include "type-db.h"

typedef enum enum_guidinfo_type
{
	GT_STRING,
	GT_WCSTRING,
	GT_CHAR,
	GT_WCHAR,
	GT_LONG,
	GT_SHORT,
	GT_PARA,
	GT_PROC,
	GT_COMMENT,
	GT_TYPE,
	GT_FUNCTION,
	GT_ID,
} GUIDINFO_TYPE;


#pragma pack(push,1)

typedef struct tagtext_rec
{
	unsigned int address;
	char * text;
} TEXT_REC,*PTEXT_REC;

typedef struct tagdata
{
	unsigned int address;
	int num;
	PGENERAL_TYPE type_info;
	char * name;
} DATA_REC,*PDATA_REC;

typedef  PARAMETERINFO VAR_REC,*PVAR_REC;

typedef struct tagpara_rec
{
	unsigned int address;
	char * text;
	char reg_no;
}PARAMETER_REC,*PPARAMETER_REC;

typedef struct tagprocedure_rec
{
	unsigned int address;
	char * name;
	char type; //  0-c function, 1- asm proc
	union 
	{
	SLIST parameter_list;
	SLIST var_list;
	};
} PROCEDURE_REC,*PPROCEDURE_REC;

#define  PROC_TYPE_CFUNCTION 1
#define  PROC_TYPE_ASMPROC 0
typedef struct tagtype_rec
{
	unsigned int address;
	PGENERAL_TYPE type_info;
} TYPE_REC,*PTYPE_REC;

#pragma pack(pop)
PTEXT_REC lookup_commentrec( unsigned int addr);
PDATA_REC lookup_datarec( unsigned int addr);
PTYPE_REC lookup_type( unsigned int addr);
PPROCEDURE_REC lookup_proc( unsigned int addr);
PPARAMETER_REC lookup_parameter( unsigned int addr);

char get_regno(char * name, int len);
void add_comments( unsigned int address, char * comments);
void add_parameter( unsigned int address, char reg_no,char * comments);
void add_procedure( unsigned int address, char * name,char type);
void add_data( unsigned int address, char * name,PGENERAL_TYPE type, int num);
void add_type( unsigned int address, PGENERAL_TYPE type);
bool add_var(unsigned int address_of_proc,int off,char *name,int name_len,PGENERAL_TYPE type_info,int num);
#endif // __guidinfo_h__