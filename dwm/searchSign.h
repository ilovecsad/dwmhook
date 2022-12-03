#pragma once
#include <Windows.h>
#include <Psapi.h>

BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD64 FindPattern(const char* szModule, BYTE* bMask, const char* szMask);
void ck_printf(const char* Format, ...);

