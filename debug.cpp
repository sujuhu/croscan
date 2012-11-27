#include <stdio.h>
#include <stdarg.h>
#include "debug.h"

bool g_debug = false;

void dprintf( const char* lpszFormat, ... )
{
	if (g_debug) {
		char sError[1024] = {0};
		va_list argList;
		va_start( argList, lpszFormat );
		_vsnprintf(sError, 1024 - 1, lpszFormat, argList );
		printf(sError);
		va_end(argList);
	}
}