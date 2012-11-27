

typedef struct _find_api_t
{
	_FindFirstFileW 	NewFindFirstFileW;
	_FindFirstFileW 	OriFindFirstFileW
	_FindFirstFileExW 	NewFindFirstFileExW;
	_FindFirstFileExW 	OriFindFirstFileExW;
	_FindNextFileW		NewFindNextFileW;
	_FindNextFileW		OriFindNextFileW;
	_FindClose			NewFindClose;
	_FindClose			OriFindClose;
}find_api_t;


errno_t HookFindApi(find_api_t* api);