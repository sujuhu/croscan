#ifndef CROSCAN_AVCTRL_H__
#define CROSCAN_AVCTRL_H__

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

#define INVALID_SCANNER  	(int)0

//创建一个scanner
int create_scanner(const char* name, const char* cmdline, 
	const char* path,
	const char* sample_dir);

//扫描样本文件
int scan_file(int sd, const char* sample_file);

uint32_t get_scanner_pid(int sd);

//关闭Scanner
void close_scanner(int sd);

bool is_scanner_idle(int sd);

#ifdef  __cplusplus
}
#endif

#endif
