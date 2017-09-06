#ifndef CONFIGMGR_H_
#define CONFIGMGR_H_

#include <stdio.h>

/** Ѱ�Ҳ�����ʶͷ
 *
 *  ���ļ��ж�λ�������ı�ʶ
 *  @param:  char * header ������ʶ�ַ���
 *  @return: [int]  �Ƿ�ɹ�
 *  @note:   
 *  @see:    
 */ 
int find_header( FILE *fp,char * header);

// �ѱ�����ת��Ϊ�ַ������
#define TOSTRING(name) #name 

// д�������ʶͷ
#define WRITE_PARAM_HEADER(fp,Header) \
	fprintf(fp,"%s\n",Header)

#define FIND_PARAM_HEADER(fp,Header) \
	find_header(fp,Header)

// ���������,int����
#define SAVE_PARAM_INT(fp,Key,Value) \
	fprintf(fp,"%s %d\n",#Key,Value)

// ���������,�ַ�������
#define SAVE_PARAM_STR(fp,Key,Value) \
	fprintf(fp,"%s %s\n",#Key,Value)

// ��ȡ������,int����
#define LOAD_PARAM_INT(fp,KeyAddr,ValueAddr) \
	fscanf(fp,"%s %d",KeyAddr,ValueAddr)

// ��ȡ������,�ַ�������
#define LOAD_PARAM_STR(fp,KeyAddr,ValueAddr) \
	fscanf(fp,"%s %s",KeyAddr,ValueAddr)



#endif  // CONFIGMGR_H_