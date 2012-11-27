#ifndef CROSCAN_AVFLUSH_H__
#define CROSCAN_AVFLUSH_H__

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

typedef int (__cdecl *_fflush_)(FILE* _File);
typedef int (__cdecl *_flushall_)(void);

typedef struct _flush_t{
	int 		method;
	unsigned long addr_iob;
	_fflush_ 	fflush;
	_flushall_ 	flush_all;
}flush_t;

errno_t SearchFlush1(flush_t* f);

errno_t SearchFlush2(flush_t* f);

errno_t SearchFlush3(flush_t* f);


#ifdef  __cplusplus
}
#endif

#endif