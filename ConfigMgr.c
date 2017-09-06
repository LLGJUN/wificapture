#include "ConfigMgr.h"
#include <string.h>

int find_header( FILE *fp,char * header)
{
	char keyName[100];

	if( fp == NULL )
	{
		return -1;
	}

	while( !feof(fp) )
	{
		fscanf(fp,"%s",keyName);
		if( strcmp(keyName,header) == 0 )
		{
			return 0;
		}
	} 

	printf("cannot find %s in file \n",header);

	return -1;
}