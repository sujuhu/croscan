#ifndef	  _QSCANNER_PROCESS_MESSAGE_
#define	  _QSCANNER_PROCESS_MESSAGE_

#ifndef MAX_ENGINE_NAME
#define	MAX_ENGINE_NAME			128
#endif

#ifndef MAX_RESULT_LENGTH
#define MAX_RESULT_LENGTH		512
#endif

typedef struct _PM_ENGINE_NAME
{		
	char name[MAX_ENGINE_NAME];
}PM_ENGINE_NAME;

typedef struct _PM_SCAN_REPORT
{
	char result[MAX_RESULT_LENGTH];
}PM_SCAN_REPORT;

//样本扫描请求
typedef struct _sample_t
{
	uint32_t msgid;
	char file[MAX_PATH];
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	WCHAR  cFileName[MAX_PATH];
}sample_t;

//slave 启动参数
typedef struct _atach_t
{
	uint32_t msgid;
	bool win7_laster;
	char name[MAX_ENGINE_NAME];
	wchar_t scanfolder[MAX_PATH];
	int force_flush;
}atach_t;

typedef struct _init_t
{
	bool is_win7_laster;
}init_t;

#define PMSG_SCAN			1
#define PMSG_ENGINE_NAME	2
#define PMSG_REPORT			3
#define PMSG_ATACH			4
#define PMSG_EXIT			5
#define PMSG_WAIT_UTIL_READY			6
#define PMSG_DEATACH		7
#define PMSG_INIT			8
#define PMSG_READY    		9

#endif