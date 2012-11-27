#pragma warning(disable:4996)
#include "typedef.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <windows.h>
//#include <winternl.h>
#include <detours.h>
#include <pipe.h>
#include <shlwapi.h>
#include "psmsg.h"
#include "ntdll.h"
#include "avflush.h"

bool MakeHexString(uint8_t* buffer, int size, char* hex, int max_cch)
{
	if( buffer == NULL || hex == NULL)
		return false;

	if (max_cch < (size * 2)) {
		return false;
	}

	memset(hex, 0, max_cch);
	for (int i = 0; i < size; i++ ) {
		char tmp[3] = {0}; 
		_snprintf(tmp, sizeof(tmp), "%02X", buffer[i] );
		strncat(hex, tmp, sizeof(tmp) - 1);
	}

	return true;
}

typedef 
BOOL
( WINAPI *_FindNextFileW )(
		IN  HANDLE hFindFile,
		OUT LPWIN32_FIND_DATAW lpFindFileData
		);

typedef 
HANDLE
( WINAPI *_FindFirstFileW )(
			   IN  LPCWSTR lpFileName,
			   OUT LPWIN32_FIND_DATAW lpFindFileData
			   );

typedef 
HANDLE
( WINAPI *_FindFirstFileExW )(
		 IN       LPCWSTR lpFileName,
		 IN       FINDEX_INFO_LEVELS fInfoLevelId,
		 OUT      LPVOID lpFindFileData,
		 IN       FINDEX_SEARCH_OPS fSearchOp,
		 LPVOID lpSearchFilter,
		 IN       DWORD dwAdditionalFlags
		 );

typedef
BOOL
( WINAPI *_FindClose )(
		 IN OUT HANDLE hFindFile
		 );

typedef 
NTSTATUS 
(WINAPI *_ZwQueryInformationFile)(
  IN HANDLE FileHandle,
  OUT PIO_STATUS_BLOCK IoStatusBlock,
  OUT  PVOID FileInformation,
  IN   ULONG Length,
  IN   FILE_INFORMATION_CLASS FileInformationClass
);

typedef 
NTSTATUS
(WINAPI *_ZwQueryDirectoryFile)(
	IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID  ApcContent,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG  Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileMask,
	IN BOOLEAN RestartScan
);

typedef struct _FILE_NAME_INFORMATION {
  ULONG  FileNameLength;
  WCHAR  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _engine_t
{
	bool	have_inited;
	char 	name[MAX_ENGINE_NAME];
	wchar_t 	scanfolder[MAX_PATH];
	uint32_t pid_server;
	sample_t current_file;
	HANDLE	scan_event;
	HANDLE  ready_event;
	HANDLE  scan_handle;
	int pipe;
	_FindFirstFileExW FindFirstFileExW;
	_FindNextFileW	FindNextFileW;
	_FindClose		FindClose;
	_ZwQueryInformationFile ZwQueryInformationFile;
	_ZwQueryDirectoryFile ZwQueryDirectoryFile;
	int	flush_method;
	bool win7_laster;
	flush_t flush;
}engine_t;

engine_t g_engine = {0};


PVOID FindFunctionAddress( const char* modname, char* funcname )
{
	HMODULE	hMod = GetModuleHandle( modname );
	if( hMod == NULL )
		return NULL;

	return (PVOID)GetProcAddress( hMod, funcname );
}

/*
void EngineFlush()
{
	switch( g_engine.flush.method ) 
	{
	case 0:
		break;
	case 1:
	case 2:
		{	
			g_engine.flush.fflush((FILE*)(g_engine.flush.addr_iob + 1));
		}
		break;
	case 3:
		{
			if( g_engine.flush.flush_all ){
				g_engine.flush.flush_all();
			}
		}
		break;
	case 4:
		{
			HANDLE* pHandle = (HANDLE*)0x004CE740;
			HANDLE	hOutput = *pHandle;
			FlushFileBuffers( hOutput );
		}
		break;
	default:
		break;
	}

}
*/

bool is_scan_folder(LPCWSTR lpFileName)
{

	if (wcsstr(lpFileName, L"__CROSCAN_SAMPLE__\\*")) {
		return true;
	} else {
		return false;
	}

	/*
	IO_STATUS_BLOCK IoStatus;
	char buffer[1024] = {0};
	NTSTATUS ret = STATUS_SUCCESS;
	ret = g_engine.ZwQueryDirectoryFile(file_handle, NULL, NULL, NULL,
  					&IoStatus, buffer, sizeof(buffer), FileNamesInformation, 
  					TRUE, NULL, FALSE);
  	if (ret != STATUS_SUCCESS) {
  		OutputDebugString("ZwQueryInformationFile failed");
  		char msg[64] = {0};
  		_snprintf(msg, sizeof(msg), "retcode: %08x", ret);
  		OutputDebugString(msg);
  		return false;
  	}

 	FILE_NAME_INFORMATION* name = (FILE_NAME_INFORMATION*)buffer;
	if (wcsstr(name->FileName, L"__CROSCAN_SAMPLE__")) {
		//打开的是扫描目录
		return true;
	} else {
		return false;
	}
	*/
}

bool read_sample(LPWIN32_FIND_DATAW lpFindFileData)
{
	//获取所要扫描的文件信息
	uint32_t msg = PMSG_SCAN;
	int nb = write_pipe(g_engine.pipe, &msg, sizeof(msg));
	if (nb != sizeof(msg)) {
		return false;
	}

	sample_t sample = {0};
	nb = read_pipe(g_engine.pipe, (uint8_t*)&sample, sizeof(sample_t));
	if (nb != sizeof(sample_t)) {
		return false;
	}

	lpFindFileData->ftCreationTime = sample.ftCreationTime;
	lpFindFileData->ftLastAccessTime = sample.ftLastAccessTime;
	lpFindFileData->ftLastWriteTime = sample.ftLastWriteTime;
	lpFindFileData->dwFileAttributes = sample.dwFileAttributes;
	lpFindFileData->nFileSizeHigh = sample.nFileSizeHigh;
	lpFindFileData->nFileSizeLow = sample.nFileSizeLow;
	memset(lpFindFileData->cFileName, 0, sizeof(lpFindFileData->cFileName));
	memcpy(lpFindFileData->cFileName, sample.cFileName, 
		sizeof(lpFindFileData->cFileName));
	memset(lpFindFileData->cAlternateFileName, 0, sizeof(lpFindFileData->cAlternateFileName));
	return true;
}

HANDLE WINAPI EngineFindFirstFileExW(
		 IN       LPCWSTR lpFileName,
		 IN       FINDEX_INFO_LEVELS fInfoLevelId,
		 OUT      LPVOID lpFindFileData,
		 IN       FINDEX_SEARCH_OPS fSearchOp,
		 LPVOID lpSearchFilter,
		 IN       DWORD dwAdditionalFlags
		 )
{
	HANDLE hfind = g_engine.FindFirstFileExW(lpFileName, fInfoLevelId,
		lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	OutputDebugStringW(lpFileName);
	if (is_scan_folder(lpFileName)) {
		OutputDebugString("Is scan folder");
		if (g_engine.scan_handle == NULL) {
			OutputDebugString("Get Handle");
			g_engine.scan_handle =  hfind;
		}
	} 

	return hfind;	
}

BOOL WINAPI EngineFindNextFileW(
	IN  HANDLE hFindFile,
	OUT LPWIN32_FIND_DATAW lpFindFileData)
{
	//分析hFindFile是否是扫描目录
	if (hFindFile != g_engine.scan_handle) {
		//不是扫描目录
		//OutputDebugString("Original FindNextFileW...");
		return g_engine.FindNextFileW(hFindFile, lpFindFileData);
	} else {
		//是指定的扫描目录
		//通知引擎控制端， 已经准备就绪
		static bool notify = false;
		if (!notify) {
			uint32_t msg = PMSG_READY;
			write_pipe(g_engine.pipe, &msg, sizeof(msg));
			notify = true;
			return g_engine.FindNextFileW(hFindFile, lpFindFileData);
		}

		/*
		OutputDebugString("Hooked FindNextFileW......");
		//从服务器队列中读取样本
		//WIN32_FIND_DATAW test = {0};
		
		g_engine.FindNextFileW(hFindFile, lpFindFileData);
		
		char str[2048] = {0};
		MakeHexString((uint8_t*)lpFindFileData, sizeof(WIN32_FIND_DATAW), str, sizeof(str)-1 );
		WIN32_FIND_DATAW data = {0};
		memcpy(&data, lpFindFileData, sizeof(WIN32_FIND_DATAW));
		
		//OutputDebugString(str);
		//OutputDebugStringW( lpFindFileData->cFileName );
		*/
		if (!read_sample(lpFindFileData)) {
			OutputDebugString("Fetch Sample failed");
			return FALSE;
		} 
		
		/*
		char str2[2048] = {0};
		MakeHexString((uint8_t*)lpFindFileData, sizeof(WIN32_FIND_DATAW), str2, sizeof(str2)-1 );
		if (memcmp(str, str2, 2048) == 0 ){
			OutputDebugString("Match");
		} else {
			OutputDebugString("NOT Match");
			if (0 != memcpy(&data.ftCreationTime, &lpFindFileData->ftCreationTime, 
				sizeof(data.ftCreationTime))) {
				OutputDebugString("ftCreationTime not match");
			}
			if (0 != memcmp(&data.ftLastAccessTime, &lpFindFileData->ftLastAccessTime,
				sizeof(data.ftLastAccessTime))) {
				OutputDebugString("ftLastAccessTime not match");
			}
			if (0 != memcmp(&data.ftLastWriteTime, &lpFindFileData->ftLastWriteTime,
				sizeof(data.ftLastWriteTime))) {
				OutputDebugString("ftLastWriteTime not match");
			}

			if (data.dwFileAttributes != lpFindFileData->dwFileAttributes) {
				OutputDebugString("dwFileAttributes not match");
			}

			if (data.nFileSizeHigh != lpFindFileData->nFileSizeHigh) {
				OutputDebugString("nFileSizeHigh not match");
			}

			if (data.nFileSizeLow != lpFindFileData->nFileSizeLow) {
				OutputDebugString("nFileSizeLow not match");
			}

			if (data.dwReserved0 != lpFindFileData->dwReserved0) {
				OutputDebugString("dwReserved0 not match");
			}

			if (data.dwReserved1 != lpFindFileData->dwReserved1) {
				OutputDebugString("dwReserved1 not match");
			}

			if (0 != wcscmp(data.cFileName, lpFindFileData->cFileName)) {
				OutputDebugString("cFileName not match");
			}

			if (0!= wcscmp(data.cAlternateFileName, lpFindFileData->cAlternateFileName)) {
				OutputDebugString("cAlternateFileName not match");
				OutputDebugStringW(data.cAlternateFileName);
				OutputDebugStringW(lpFindFileData->cAlternateFileName);
			}
		}
		*/
		//OutputDebugString(str);
		//DebugBreak();
		OutputDebugStringW( lpFindFileData->cFileName );
		SetLastError(0);
		return TRUE;
		
		/*
		BOOL ret = g_engine.FindNextFileW(hFindFile, lpFindFileData);
		OutputDebugStringW(lpFindFileData->cAlternateFileName);
		OutputDebugStringW( lpFindFileData->cFileName );
		return ret;
		*/

		/*


		//FlushProcessWriteBuffers();
		//FlushFileBuffers( GetStdHandle( STD_OUTPUT_HANDLE ) );
		//FlushConsoleInputBuffer( GetStdHandle( STD_OUTPUT_HANDLE ) );


		*/
	}
}

//卸载反病毒引擎
errno_t DeatachEngine()
{
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	DetourDetach((PVOID*)g_engine.FindNextFileW, (PVOID*)EngineFindNextFileW );
	DetourTransactionCommit();
	return true;
}

/*
errno_t HookStdout2()
{
	HANDLE hSaveOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if( hSaveOutput == NULL ) {
		OutputDebugString( "GetStdHandle failed\n" );
		return EINVAL;
	}

	int hout = _open_osfhandle( (long)hSaveOutput, _O_BINARY );
	if( hout == -1 ) {
		OutputDebugString( "_open_osfhandle failed" );
		return EINVAL;
	}

	FILE* hf = _fdopen( hout, "w");
	if( hf == NULL ) {
		OutputDebugString( "_fdopen failed" );
		return EINVAL;
	}
	*stdout = *hf;
	setvbuf(stdout, NULL, _IONBF ,0);
	return 0;
}
*/

//加载反病毒引擎
errno_t atach_engine(/*wchar_t* scanfolder,  int force_flush_method*/)
{
	if (g_engine.have_inited) {
		return EEXIST;
	}

	uint32_t pid = GetCurrentProcessId();
	char pipename[1024] = {0};
	_snprintf(pipename, sizeof(pipename) - 1, "avctrl_%d", pid);
	g_engine.pipe = open_pipe(pipename);
	if (g_engine.pipe == INVALID_PIPE) {
		OutputDebugString("open pipe failed");
		OutputDebugString(pipename);
		return ENOENT;
	}

	uint32_t msg = PMSG_INIT;
	int nb = write_pipe(g_engine.pipe, &msg, sizeof(msg));
	if (nb != sizeof(msg)) {
		OutputDebugString("write pipe failed");
		return EINVAL;
	}

	init_t init = {0};
	nb = read_pipe(g_engine.pipe, &init, sizeof(init_t));
	if (nb != sizeof(init_t)) {
		OutputDebugString("read pipe failed");
		return EINVAL;
	}

	g_engine.win7_laster = init.is_win7_laster;
	//memcpy(g_engine.scanfolder, scanfolder, sizeof(g_engine.scanfolder));

	//创建文件扫描事件， 用于同步文件扫描请求
	/*
	g_engine.scan_event = CreateEvent( NULL, FALSE, FALSE, NULL );
	if (NULL == g_engine.scan_event) {
		return GetLastError();
	}

	g_engine.ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (NULL == g_engine.ready_event) {
		return GetLastError();
	}
	*/

	//Hook FindNextFileW函数
	const char* modname = NULL;
	if( g_engine.win7_laster) {
		modname = "kernelbase.dll";
	} else {
		modname = "kernel32.dll";
	}
	g_engine.FindNextFileW
		= (_FindNextFileW)FindFunctionAddress(modname, (char*)"FindNextFileW");
	if( g_engine.FindNextFileW == NULL ) {
		OutputDebugString( "FindNextFileW is NULL" );
		return GetLastError();
	}

	g_engine.FindFirstFileExW
	 	= (_FindFirstFileExW)FindFunctionAddress(modname, (char*)"FindFirstFileExW");
	if (g_engine.FindFirstFileExW == NULL) {
		OutputDebugString("FindFirstFileExW is NULL");
		return GetLastError();
	}

	g_engine.ZwQueryInformationFile
		= (_ZwQueryInformationFile)FindFunctionAddress("ntdll", (char*)"ZwQueryInformationFile");
	if( g_engine.ZwQueryInformationFile == NULL ) {
		OutputDebugString( "ZwQueryInformationFile is NULL" );
		return GetLastError();
	}

	g_engine.ZwQueryDirectoryFile
		= (_ZwQueryDirectoryFile)FindFunctionAddress("ntdll", (char*)"ZwQueryDirectoryFile");
	if (g_engine.ZwQueryDirectoryFile == NULL) {
		OutputDebugString("ZwQueryDirectoryFile is NULL");
		return GetLastError();
	}	

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (NO_ERROR != DetourAttach((PVOID*)&g_engine.FindFirstFileExW, 
		(PVOID)EngineFindFirstFileExW)) {
		OutputDebugString( "DetourAttach FindFirstFileExW Failed");
		return GetLastError();
	}

	if( NO_ERROR != DetourAttach((PVOID*)&g_engine.FindNextFileW, 
		(PVOID)EngineFindNextFileW)) {
		OutputDebugString( "DetourAttach FindNextFileW Failed" );
		return GetLastError();
	}

	if( NO_ERROR != DetourTransactionCommit() ) {
		OutputDebugString( "DetourTransactionCommit Failed" );
		return GetLastError();
	}

	//重定向输出
	/*
	if (!HookStdout2()) {
		OutputDebugString( "hook stdout failed" );
		return -1;
	}
	*/

	/*
	switch(force_flush_method)
	{
	case 0:
		break;
	case 1:
		if( !SearchFlush1(&g_engine.flush) ) {
			OutputDebugString( "search fflush failed" );
			return -1;
		}
		break;
	case 2:
		if( !SearchFlush2(&g_engine.flush) ) {
			OutputDebugString( "search 2 fflush failed");
			return -1;
		}
		break;
	case 3:
		if( !SearchFlush3(&g_engine.flush) ) {
			OutputDebugString( "search 3 fflush failed" );
			return -1;
		}
		break;
	default:
		break;
	}
	*/

	//初始化完成
	g_engine.have_inited = true;
	OutputDebugString( "engine init successfully\n" );
	return 0;
}

//DWORD WINAPI InitProcessPipe(LPVOID lpThreadParameter)
/*
DWORD WINAPI WorkThread(LPVOID lpThreadParameter)
{
	OutputDebugString( "init engine comm....\n" );

	uint32_t pid = GetCurrentProcessId();
	char pipename[MAX_PATH] = {0};
	_snprintf(pipename, sizeof(pipename), "avctrl", pid);
	g_engine.pipe = connect_pipe(pipename);
	if (g_engine.pipe == INVALID_PIPE) {
		OutputDebugString("connect pipe failed");
		return 0;
	}


	return 0;
}
*/

BOOL APIENTRY DllMain( HMODULE hModule,
		      DWORD  ul_reason_for_call,
		      LPVOID lpReserved
		      )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			
		}
	case DLL_THREAD_ATTACH:
		{
			static bool is_inited = false;

			if( !is_inited ) {
				//CreateThread(0, 0, WorkThread, NULL, 0, 0);
				atach_engine();
				is_inited = true;
			}
		}
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		{
			//uninit_engine();
		}
		break;
	}
	return true;
}
