#include "typedef.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <filemap.h>
#include <pe.h>
#include <memhelp.h>
#include "avflush.h"

typedef 
DWORD
(WINAPI *_GetModuleFileNameExA)(
    IN HANDLE hProcess,
    IN HMODULE hModule,
    OUT LPSTR lpFilename,
    IN DWORD nSize
    );

errno_t SearchFlush1(flush_t* f)
{
	unsigned char* pos = NULL;

	char filename[MAX_PATH] = {0};
	HMODULE base = GetModuleHandle( NULL );

	HMODULE psapi = LoadLibrary("psapi.dll");
	if (psapi == NULL)
		return -1;
	_GetModuleFileNameExA GetModuleFileNameEx_ = 
		(_GetModuleFileNameExA)GetProcAddress(psapi, "GetModuleFileNameExA");
	GetModuleFileNameEx_(GetCurrentProcess(), base, filename, sizeof(filename));
	
	MAPPED_FILE view = {0};
	if( !map_file(filename, &view) ) {
		return errno;
	}

	int pe = pe_open((const char*)view.data, view.size);
	if (pe == INVALID_PE) {
		unmap_file(&view);
		return errno;
	}

	//搜索_fflush函数
	/*
					_fflush         proc near               ; CODE XREF: sub_403AD0+2A0p
	.text:004E6AD9                                                           ; output_result+A5p ...
	.text:004E6AD9
	.text:004E6AD9                   var_1C          = dword ptr -1Ch
	.text:004E6AD9                   ms_exc          = CPPEH_RECORD ptr -18h
	.text:004E6AD9                   File            = dword ptr  8
	.text:004E6AD9
	.text:004E6AD9 6A 0C                             push    0Ch
	.text:004E6ADB 68 58 7B 51 00                    push    offset unk_517B58
	.text:004E6AE0 E8 1F 64 00 00                    call    __SEH_prolog4
	.text:004E6AE5 33 F6                             xor     esi, esi
	.text:004E6AE7 39 75 08                          cmp     [ebp+File], esi
	.text:004E6AEA 75 09                             jnz     short loc_4E6AF5
	.text:004E6AEC 56                                push    esi
	.text:004E6AED E8 0D FF FF FF                    call    _flsall
	.text:004E6AF2 59                                pop     ecx
	.text:004E6AF3 EB 27                             jmp     short loc_4E6B1C
	.text:004E6AF5                   ; ---------------------------------------------------------------------------
	.text:004E6AF5
	.text:004E6AF5                   loc_4E6AF5:                             ; CODE XREF: _fflush+11j
	.text:004E6AF5 FF 75 08                          push    [ebp+File]
	.text:004E6AF8 E8 94 FD FF FF                    call    __lock_file
	.text:004E6AFD 59                                pop     ecx
	.text:004E6AFE 89 75 FC                          mov     [ebp+ms_exc.disabled], esi
	.text:004E6B01 FF 75 08                          push    [ebp+File]      ; File
	.text:004E6B04 E8 B4 FE FF FF                    call    __fflush_nolock
	.text:004E6B09 59                                pop     ecx
	.text:004E6B0A 89 45 E4                          mov     [ebp+var_1C], eax
	.text:004E6B0D C7 45 FC FE FF FF+                mov     [ebp+ms_exc.disabled], 0FFFFFFFEh
	.text:004E6B14 E8 09 00 00 00                    call    $LN8_1
	.text:004E6B19
	.text:004E6B19                   $LN9_1:
	.text:004E6B19 8B 45 E4                          mov     eax, [ebp+var_1C]
	.text:004E6B1C
	.text:004E6B1C                   loc_4E6B1C:                             ; CODE XREF: _fflush+1Aj
	.text:004E6B1C E8 28 64 00 00                    call    __SEH_epilog4
	.text:004E6B21 C3                                retn
	.text:004E6B21                   _fflush         endp

	*/
	uint8_t taget_fflush_1[] = { 0x33, 0xF6, 0x39, 0x75, 0x08, 0x75, 0x09, 0x56, 0xE8 };

	char* start = (char*)view.data;
	while( start < ((char*) view.data + view.size ) ) {
		start = (char*)memstr((const char*)start, view.size - (start - (char*)view.data), 
			(const char*)taget_fflush_1, sizeof( taget_fflush_1 ) );
		if( start == NULL ) {
			break;
		}

		uint8_t target_fflush_2[] = { 0x59, 0xEB, 0x27, 0xFF, 0x75, 0x08, 0xE8 };
		uint8_t target_fflush_3[] = { 0x59, 0x89, 0x75, 0xFC, 0xFF, 0x75, 0x08, 0xE8 };
		if( 0 == memcmp( start + 0xD, target_fflush_2, sizeof( target_fflush_2 ))
		 && 0 == memcmp( start + 0x18, target_fflush_3, sizeof( target_fflush_3 ))) {
			//找到了
			break;
		}

		start += sizeof( taget_fflush_1 );
	}

	if( start == NULL ) {
		pe_close(pe);
		unmap_file( &view );
		return errno;
	}

	//将物理地址转换成虚拟地址
	f->fflush = (_fflush_)(raw_to_rva(pe, (uint32_t)(start - 0xC - (char*)view.data)));
	if( (ULONG)f->fflush == INVALID_RVA ) {
		pe_close(pe);
		unmap_file( &view );
		return errno;
	}

	//搜索__lock_file函数，得到iob数据的地址
	//从而可以获取到stdout
	/*
	.text:004E6891 56                                push    esi
	.text:004E6892 8B 74 24 08                       mov     esi, [esp+4+arg_0]
	.text:004E6896 B8 D0 EF 51 00                    mov     eax, offset __iob
	.text:004E689B 3B F0                             cmp     esi, eax
	.text:004E689D 72 22                             jb      short loc_4E68C1
	.text:004E689F 81 FE 30 F2 51 00                 cmp     esi, offset unk_51F230
	.text:004E68A5 77 1A                             ja      short loc_4E68C1
	.text:004E68A7 8B CE                             mov     ecx, esi
	.text:004E68A9 2B C8                             sub     ecx, eax
	.text:004E68AB C1 F9 05                          sar     ecx, 5
	.text:004E68AE 83 C1 10                          add     ecx, 10h
	.text:004E68B1 51                                push    ecx
	.text:004E68B2 E8 1B 5B 00 00                    call    __lock
	.text:004E68B7 81 4E 0C 00 80 00+                or      dword ptr [esi+0Ch], 8000h
	.text:004E68BE 59                                pop     ecx
	.text:004E68BF 5E                                pop     esi
	.text:004E68C0 C3                                retn
	*/

	uint8_t target[] = { 0x77, 0x1A, 0x8B, 0xCE, 0x2B, 0xC8, 0xC1, 0xF9, 0x05, 0x83, 0xC1, 0x10, 0x51, 0xE8 };
	pos = (uint8_t*)memstr((const char*)view.data, view.size, 
					(const char*)target, sizeof( target ) );
	pos -= 0xE;
	f->addr_iob = *(unsigned long*)pos;
	
	pe_close(pe);
	unmap_file( &view );
	return true;
}

errno_t SearchFlush2(flush_t* f)
{
	unsigned char* pos = NULL;

	char filename[MAX_PATH] = {0};
	HMODULE base = GetModuleHandle( NULL );

	HMODULE psapi = LoadLibrary("psapi.dll");
	if (psapi == NULL)
		return -1;
	_GetModuleFileNameExA GetModuleFileNameEx_ = 
		(_GetModuleFileNameExA)GetProcAddress(psapi, "GetModuleFileNameExA");

	GetModuleFileNameEx_( GetCurrentProcess(), base, filename, sizeof( filename ) );

	MAPPED_FILE view = {0};
	if( !map_file( filename, &view) ) {
		return errno;
	}

	int pe = pe_open((const char*)view.data, view.size);
	if (pe == INVALID_PE) {
		unmap_file(&view);
		return errno;
	}
 
	/*	
			_fflush         proc near
	.text:0040772E
	.text:0040772E                   File            = dword ptr  4
	.text:0040772E
	.text:0040772E 56                                push    esi
	.text:0040772F 8B 74 24 08                       mov     esi, [esp+4+File]
	.text:00407733 85 F6                             test    esi, esi
	.text:00407735 75 09                             jnz     short loc_407740
	.text:00407737 56                                push    esi
	.text:00407738 E8 B3 00 00 00                    call    _flsall
	.text:0040773D 59                                pop     ecx
	.text:0040773E 5E                                pop     esi
	.text:0040773F C3                                retn
	.text:00407740                   ; ---------------------------------------------------------------------------
	.text:00407740
	.text:00407740                   loc_407740:                             ; CODE XREF: _fflush+7j
	.text:00407740 57                                push    edi
	.text:00407741 56                                push    esi
	.text:00407742 E8 44 EA FF FF                    call    __lock_file
	.text:00407747 56                                push    esi
	.text:00407748 E8 10 00 00 00                    call    __fflush_lk
	.text:0040774D 56                                push    esi
	.text:0040774E 8B F8                             mov     edi, eax
	.text:00407750 E8 88 EA FF FF                    call    __unlock_file
	.text:00407755 83 C4 0C                          add     esp, 0Ch
	.text:00407758 8B C7                             mov     eax, edi
	.text:0040775A 5F                                pop     edi
	.text:0040775B 5E                                pop     esi
	.text:0040775C C3                                retn
	.text:0040775C                   _fflush         endp
	*/
	unsigned char taget_fflush_1[] = { 0x56, 0x8B, 0x74, 0x24, 0x08, 0x85, 0xF6, 0x75, 0x09, 0x56, 0xE8 };

	char* start = (char*)view.data;
	while( start < ((char*) view.data + view.size ) ) {
		start = (char*)memstr( (const char*)start, view.size - (start - (char*)view.data ), 
			(const char*)taget_fflush_1, sizeof( taget_fflush_1 ) );
		if( start == NULL ) {
			break;
		}

		unsigned char target_fflush_2[] = { 0x59, 0x5E, 0xC3, 0x57, 0x56, 0xE8 };
		unsigned char target_fflush_3[] = { 0x56, 0x8B, 0xF8, 0xE8 };
		if( 0 == memcmp( start + 0xF, target_fflush_2, sizeof( target_fflush_2 ))
			&& 0 == memcmp( start + 0x1F, target_fflush_3, sizeof( target_fflush_3 ))) {
				//找到了
				break;
		}

		start += sizeof( taget_fflush_1 );
	}

	if( start == NULL ) {
		f->addr_iob = 0;
		f->fflush = NULL;
		pe_close(pe);
		unmap_file(&view);
		return errno;
	}

	//将物理地址转换成虚拟地址
	f->fflush = (_fflush_)(raw_to_rva(pe, (uint32_t)(start - (char*)view.data)));
	if( (ULONG)f->fflush == INVALID_RVA) {
		f->addr_iob = 0;
		f->fflush = NULL;
		pe_close(pe);
		unmap_file( &view );
		return errno;
	}
	/*
			__lock_file     proc near               ; CODE XREF: _fclose+16p
	.text:0040618B                                                           ; sub_404D03+8p ...
	.text:0040618B
	.text:0040618B                   arg_0           = dword ptr  4
	.text:0040618B
	.text:0040618B 8B 44 24 04                       mov     eax, [esp+arg_0]
	.text:0040618F B9 80 49 41 00                    mov     ecx, __iob
	.text:00406194 3B C1                             cmp     eax, ecx
	.text:00406196 72 17                             jb      short loc_4061AF
	.text:00406198 3D E0 4B 41 00                    cmp     eax, offset unk_414BE0
	.text:0040619D 77 10                             ja      short loc_4061AF
	.text:0040619F 2B C1                             sub     eax, ecx
	.text:004061A1 C1 F8 05                          sar     eax, 5
	.text:004061A4 83 C0 1C                          add     eax, 1Ch
	.text:004061A7 50                                push    eax
	.text:004061A8 E8 B9 F4 FF FF                    call    __lock
	.text:004061AD 59                                pop     ecx
	.text:004061AE C3                                retn
	.text:004061AF                   ; ---------------------------------------------------------------------------
	.text:004061AF
	.text:004061AF                   loc_4061AF:                             ; CODE XREF: __lock_file+Bj
	.text:004061AF                                                           ; __lock_file+12j
	.text:004061AF 83 C0 20                          add     eax, 20h
	.text:004061B2 50                                push    eax             ; lpCriticalSection
	.text:004061B3 FF 15 78 10 41 00                 call    ds:EnterCriticalSection
	.text:004061B9 C3                                retn
	.text:004061B9                   __lock_file     endp
	*/
	unsigned char target[] = { 0x77, 0x10, 0x2B, 0xC1, 0xC1, 0xF8, 0x05, 0x83, 0xC0, 0x1C, 0x50, 0xE8 };
	//unsigned char target2[] = { 0x59, 0xC3, 0x83, 0xC0, 0x20, 0x50, 0xFF, 0x15 };
	pos = (uint8_t*)memstr((const char*)view.data, view.size, 
					(const char*)target, sizeof(target));
	//if( 0 == memcmp( pos + 0x10, target2, sizeof( target2 ) )) {
	//	//找到了
	//	break;
	//}
	pos -= 0xD;
	f->addr_iob = *( unsigned long*)pos;
	pe_close(pe);
	unmap_file( &view );
	return true;

}


errno_t SearchFlush3(flush_t* f)
{
	//加载MSVCR90.dll
	HMODULE crt = LoadLibrary( "MSVCR90.dll" );
	if( crt == NULL ) {
		return FALSE;
	}

	//获取_flushall函数
	f->flush_all = (_flushall_)GetProcAddress(crt, "_flushall" );
	if( f->flush_all == NULL )
		return FALSE;

	return TRUE;
}
