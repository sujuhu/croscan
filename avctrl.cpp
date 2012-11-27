#pragma warning(disable:4996)
#include <stdio.h>
#include <errno.h>
#include <windows.h>
#include <shlwapi.h>
#include <direct.h>
#include "typedef.h"
#include <inject.h>
#include <pipe.h>
#include <fifo.h>
#include <md5.h>
#include <strhelp.h>
#include "debug.h"
#include "psmsg.h"
#include "avctrl.h"

#define MAX_QUEUE_SIZE   5
//引擎描述信息
typedef struct _scanner_t {
	char name[256];
	char cmdline[1024];
	char path[512];
	uint32_t pid;
	int force_flush;				//是否强行刷新缓存
	int pipe;	
	fifo_t queue;
	HANDLE hthread;
	char sample_dir[1024];
	HANDLE ready_event;
}scanner_t;

/*
//等待slaver连接
bool	CVirusScanner::WaitSlaveConnected( 
	uint32_t pid_scanner, 
	int timeout_seconds )
{
	if( !g_center.bOpening  ) {
		SetLastError( ERROR_SHUTDOWN_IN_PROGRESS );
		return false;
	}

	HANDLE hConnectNotify = GetConnectEventHandle( idEngine );
	if( hConnectNotify == NULL ) {
		return false;
	}

	if( WAIT_OBJECT_0 != WaitForSingleObject( hConnectNotify, 
		timeout_seconds * 1000 ) ) {
		//连接超时
		return false;
	}

	return true;
}


//等待slave准备就绪
bool	CVirusScanner::WaitSlaveReady(
	uint32_t pid_scanner, 
	int timeout_seconds )
{
	if( !g_center.bOpening ) {
		SetLastError( ERROR_SHUTDOWN_IN_PROGRESS );
		return false;
	}

	HANDLE hReady = GetReadyEventHandle(pid_scanner);
	if(hReady == NULL) {
		return false;
	} 

	if(WAIT_OBJECT_0 != WaitForSingleObject(hReady, 30 * 1000)) {
		return false;
	}

	return true;
}
*/


bool start_scanner(scanner_t* scanner)
{
	STARTUPINFO si = {0};
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags |= STARTF_USESTDHANDLES;
	PROCESS_INFORMATION pi = {0};
	char cwd[520] = {0};
	_getcwd(cwd, sizeof(cwd) - 1);
	_chdir(scanner->path);
	if (!CreateProcess(NULL, (LPSTR)scanner->cmdline, NULL, NULL, FALSE, 
		CREATE_SUSPENDED, NULL, 
		scanner->path, 
		&si, 
		&pi) ) {
		_chdir(cwd);
		return false;
	}

	_chdir(cwd);
	scanner->pid = pi.dwProcessId;
	scanner->hthread = pi.hThread;	
	return true;
}

bool run_scanner(scanner_t* scanner)
{
	if (-1 == ResumeThread(scanner->hthread)) {
		return false;
	}
	return true;
}

bool inject_scanner(uint32_t pid_scanner)
{
	//将slave模块远程注入到扫描器进程中
	char injectdll_path[MAX_PATH] = {0};
	_getcwd(injectdll_path, MAX_PATH);
	PathAppend(injectdll_path, "avslave.dll");
	return inject_dll_to_process(pid_scanner, injectdll_path);
}

/*
bool connect_scanner(scanner_t* scanner)
{
	char pscom_name[128] = {0};
	memset(pscom_name, 0, sizeof(pscom_name));
	_snprintf(pscom_name, sizeof(pscom_name) - 1, "_%d_avslave_", scanner->pid);
	int count = 15;
	while(count-->0) {
		//每次尝试间隔1秒
		Sleep(1000);
		//连接服务器
		scanner->pipe = open_pipe(pscom_name);
		if (scanner->pipe == INVALID_PIPE) {
			continue;
		}
	
		//连接成功
		//命令slaver进行初始化工作
		atach_t	request = {0};
		request.msgid = PMSG_ATACH;
		//wcsncpy(request.scanfolder, scan_folder, sizeof(request.scanfolder) - 1 );
		request.force_flush = scanner->force_flush;
		int nb = write_pipe(scanner->pipe, (uint8_t*)&request, sizeof(request));
		if ( sizeof(request) != nb) {
			break;
		}

		uint32_t result = 0;
		nb = read_pipe(scanner->pipe, (uint8_t*)&result, sizeof(result));
		if( nb != sizeof(uint32_t ) ) {
			return -1;
		}

		if (result != 0) {
			return -1;
		}

		//等待scanner准备就绪
		//wait_scanner_ready(scanner);
		return true;
	}	
	return false;
}*/

bool wait_scanner_ready(scanner_t* scanner)
{
	uint32_t ret = WaitForSingleObject(scanner->ready_event, 5000);
	return ret == WAIT_OBJECT_0;
}

int reset_scanner(scanner_t* scanner)
{
	//启动进程
	if (!start_scanner(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return false;
	}

	if(!inject_scanner(scanner->pid)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return false;
	}

	if(!run_scanner(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return false;
	}
	return true;
}

bool is_win7_laster()
{
	/*
   	HMODULE ntdll = LoadLibrary( "kernel32.dll" );
    if ( NULL == ntdll ) {
        return false;
    }
    */

	OSVERSIONINFO osinfo = {0};
	osinfo.dwOSVersionInfoSize = sizeof( osinfo );
	GetVersionEx( &osinfo );
	return osinfo.dwMajorVersion >= 6 && osinfo.dwMinorVersion >= 1;
}

DWORD WINAPI pipe_thread(LPVOID lpThreadParameter)
{
	dprintf("pipe thread start\n");

	uint32_t pid = GetCurrentProcessId();
	scanner_t* scanner = (scanner_t*)lpThreadParameter;

	if (!listen_pipe(scanner->pipe)) {
		close_pipe(scanner->pipe);
		return false;
	}

	while(true) {
		char buffer[1024] = {0};
		int nb = read_pipe(scanner->pipe, buffer, sizeof(buffer));
		if (nb < 0 ) {
			if (GetLastError() == 0x6D) {
				//remote disconnected
				dprintf("antivirus %s already disconnected\n", scanner->name);
			} else {
				dprintf("GetLastError:%08x, HANDLE=%08x", GetLastError(), scanner->pipe);
			}
			//disconnected
			break;
		} 

		uint32_t msgid = *(uint32_t*)buffer;
		char* data = buffer + sizeof(uint32_t);
		int data_len = nb - sizeof(uint32_t);
		dprintf("msg:%d\n", msgid);
		switch(msgid){
		case PMSG_SCAN: {	
			//从队列中取一个样本， 将其返回
			do {
				sample_t* sample = (sample_t*)fifo_get(&scanner->queue);
				if (sample == NULL) {
					Sleep(100);
					continue;
				}
				dprintf("fifo get success, %S", sample->cFileName);
				write_pipe(scanner->pipe, sample, sizeof(sample_t));
				free(sample);
				sample = NULL;	
				break;
			} while(true);

			break;	
		} case PMSG_INIT: {
			init_t init = {0};
			init.is_win7_laster = is_win7_laster();
			write_pipe(scanner->pipe, &init, sizeof(init_t));
			break;
		} case PMSG_READY: {
			SetEvent(scanner->ready_event);
			break;
		} case PMSG_EXIT: {
				ExitProcess( 0 );
				break;
		} default:
			break;
		}
	}

	close_pipe(scanner->pipe);

	dprintf("pipe thread exit");
	return 0;
}

bool start_comm(scanner_t* scanner)
{
	char pipename[1024] = {0};
	_snprintf(pipename, sizeof(pipename) - 1, "avctrl_%d", scanner->pid);
	scanner->pipe = create_pipe(pipename);
	if (scanner->pipe == INVALID_PIPE) {
		return false;
	}



	CreateThread(0, 0, pipe_thread, (void*)scanner, 0, 0);
	return true;
}

//加载启动引擎
int create_scanner(const char* name, const char* cmdline, 
	const char* path,
	const char* sample_dir)
{
	//启动进程间通信模块
	//连接成功
	scanner_t* scanner = (scanner_t*)malloc(sizeof(scanner_t));
	if (scanner == NULL) {
		errno = ENOMEM;
		return INVALID_SCANNER;
	}
	memset(scanner, 0, sizeof(scanner_t));
	strncpy(scanner->name, name, sizeof(scanner->name) - 1);
	strncpy(scanner->cmdline, cmdline, sizeof(scanner->cmdline) - 1);
	strncpy(scanner->path, path, sizeof(scanner->path) - 1);
	strncpy(scanner->sample_dir, sample_dir, sizeof(scanner->sample_dir) -1);
	fifo_init(&scanner->queue, MAX_QUEUE_SIZE);
	scanner->ready_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (scanner->ready_event == NULL) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	//启动进程
	if (!start_scanner(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	if (!start_comm(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	if (!inject_scanner(scanner->pid)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	if (!run_scanner(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	if (!wait_scanner_ready(scanner)) {
		free(scanner);
		scanner = NULL;
		errno = EINVAL;
		return INVALID_SCANNER;
	}

	return (int)scanner;
}

int scan_file(int fd, const char* sample_file)
{
	scanner_t* scanner = (scanner_t*)fd;
	if (scanner == NULL) {
		return EINVAL;
	}

	/*
	if (!is_alive(scanner)) {
		if(!reset_scanner(scanner)) {
			return EINVAL;
		}
	}
	*/

	//计算样本MD5值， 将样本复制到内部目录下
	CMD5 hash;
	hash.HashFile(sample_file);
	hash.Final();
	MD5_32 md5 = {0};
	hash.GetHash(&md5);
	char str_md5[128] = {0}; 
	MakeHexString(md5._digest, 16, str_md5, sizeof(str_md5) - 1);
	char new_file[1024] = {0};
	_snprintf(new_file, sizeof(new_file) - 1, "%s\\%s",
		scanner->sample_dir, str_md5);
	CopyFile(sample_file, new_file, TRUE);

	sample_t*	sample = (sample_t*)malloc(sizeof(sample_t));
	if (sample == NULL) {
		return EINVAL;
	}	
	memset(sample, 0, sizeof(sample_t));

	sample->msgid = PMSG_SCAN;
	const char* pos = strrchr(sample_file, '\\');
	if( pos == NULL ) {
		return -1;
	}
	strncpy(sample->file, pos + 1, sizeof(sample->file) - 1);

	//读取样本的文件属性
	sample->dwFileAttributes = GetFileAttributes(new_file);
	if (sample->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
		return -1;
	}

	//读取样本的文件时间
	HANDLE hFile = CreateFile(new_file, GENERIC_READ, 
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	do {
		if (!GetFileTime(hFile, &sample->ftCreationTime, 
			&sample->ftLastAccessTime, 
			&sample->ftLastWriteTime)) {
			break;
		}

		//读取文件的大小
		sample->nFileSizeLow = GetFileSize(hFile, &sample->nFileSizeHigh);	
	}while(false);
	CloseHandle(hFile);
	hFile = NULL;

	mbstowcs(sample->cFileName, str_md5, strlen(str_md5));

	//加入队列
	while(!fifo_put(&scanner->queue, (void*)sample)) {
		//可能队列已经满了, 继续
		Sleep(100);
	}

	return 0;
}

uint32_t get_scanner_pid(int sd)
{
	scanner_t* scanner = (scanner_t*)sd;
	return scanner->pid;
}

void close_scanner(int sd)
{
}


