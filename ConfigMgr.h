#ifndef CONFIGMGR_H_
#define CONFIGMGR_H_

#include <stdio.h>

/** 寻找参数标识头
 *
 *  在文件中定位到参数的标识
 *  @param:  char * header 参数标识字符串
 *  @return: [int]  是否成功
 *  @note:   
 *  @see:    
 */ 
int find_header( FILE *fp,char * header);

// 把变量名转换为字符串输出
#define TOSTRING(name) #name 

// 写入参数标识头
#define WRITE_PARAM_HEADER(fp,Header) \
	fprintf(fp,"%s\n",Header)

#define FIND_PARAM_HEADER(fp,Header) \
	find_header(fp,Header)

// 保存参数宏,int参数
#define SAVE_PARAM_INT(fp,Key,Value) \
	fprintf(fp,"%s %d\n",#Key,Value)

// 保存参数宏,字符串参数
#define SAVE_PARAM_STR(fp,Key,Value) \
	fprintf(fp,"%s %s\n",#Key,Value)

// 读取参数宏,int参数
#define LOAD_PARAM_INT(fp,KeyAddr,ValueAddr) \
	fscanf(fp,"%s %d",KeyAddr,ValueAddr)

// 读取参数宏,字符串参数
#define LOAD_PARAM_STR(fp,KeyAddr,ValueAddr) \
	fscanf(fp,"%s %s",KeyAddr,ValueAddr)



#endif  // CONFIGMGR_H_