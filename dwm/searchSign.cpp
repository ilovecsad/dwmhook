#include "searchSign.h"
#include <stdio.h>

BOOL bDataCompare( const BYTE* pData, const BYTE* bMask, const char* szMask )
{
	for ( ; *szMask; ++szMask, ++pData, ++bMask )
	{
		if ( *szMask == 'x' && *pData != *bMask )
			return FALSE;
	}
	return ( *szMask ) == NULL;
}
DWORD64 FindPattern( const char* szModule, BYTE* bMask, const char* szMask )
{
	MODULEINFO mi{ };
	HMODULE h = GetModuleHandleA(szModule);
	if (h) 
	{
		if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi)))
		{

			DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
			const auto dwModuleSize = mi.SizeOfImage;

			for (auto i = 0ul; i < dwModuleSize; i++)
			{
				if (bDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
					return DWORD64(dwBaseAddress + i);
			}
		}
	}
	return NULL;
}


void ck_printf( const char* Format, ... )
{
	char Buf[ MAX_PATH ] = { 0 };
	va_list Args;
	va_start( Args, Format );
	const int Count = _vsnprintf_s( Buf, _countof( Buf ) - 1, _TRUNCATE, Format, Args );
	va_end( Args );
	OutputDebugStringA( Buf );
}