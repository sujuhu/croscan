


bool HookStdout()
{
	SECURITY_ATTRIBUTES saAttr; 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	//替换掉当前进程的STD_OUTPUT
	hSaveOutput = GetStdHandle( STD_OUTPUT_HANDLE );
	if( hSaveOutput == NULL ) {
		OutputDebugString( "GetStdHandle failed\n" );
		return 0;
	}

	HANDLE _hOutputRead = NULL;
	HANDLE hOutputWrite = NULL;
	if( !CreatePipe( &_hOutputRead, &hOutputWrite, &saAttr, 256 ) ) {
		OutputDebugString( "create pipe failed\n" );
		return 0;
	}

	HANDLE hOutputRead = NULL;
	BOOL bSuccess = DuplicateHandle( GetCurrentProcess(), _hOutputRead,
					 GetCurrentProcess(),&hOutputRead,
		0, FALSE, DUPLICATE_SAME_ACCESS );
	if( !bSuccess ) {
		OutputDebugString( "DuplicateHandle failed\n" );	
		return 0;
	}

	////SetHandleInformation( Console->hOutputRead, HANDLE_FLAG_INHERIT, 0);
	CloseHandle( _hOutputRead );
	_hOutputRead = NULL;

	//将新的OuputHandle设置
	if( !SetStdHandle( STD_OUTPUT_HANDLE, hOutputWrite ) ) {
		OutputDebugString( "SetStdHandle Failed" );
		return 0;
	}

	/*AllocConsole();
		CONSOLE_SCREEN_BUFFER_INFO coninfo;
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &coninfo);

	coninfo.dwSize.Y = 1;

	SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),

		coninfo.dwSize);*/

	int hout;
	FILE *hf;
	hout = _open_osfhandle( (long)hOutputWrite, _O_BINARY );
	if( hout == -1 ) {
		OutputDebugString( "_open_osfhandle failed" );
		return false;
	}
	hf = _fdopen( hout, "w");
	if( hf == NULL ) {
		OutputDebugString( "_fdopen failed" );
		return false;
	}
	*stdout = *hf;
	setvbuf(stdout, NULL, _IONBF ,0);

	//hCrt = _open_osfhandle((intptr_t)hInPut, 0x4000);
	//if( hCrt == - 1 )
	//	return false;
	//FILE* hf2;
	//hf2 = _fdopen(hCrt, "r");
	//if( hf == NULL ) {
	//	return false;
	//}
	//*stdin = * hf2;   


	//创建一个线程专门用来传输自身的输出数据
	DWORD idThread = 0;
	CreateThread( NULL, 0, ReadThread, hOutputRead, 0, &idThread );
	OutputDebugString( "redirect output" );
	
	/*while( TRUE ) {
		printf( "test\n" );
		Sleep( 1000 );
	}*/

	return true;
}
