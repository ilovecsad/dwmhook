#include "AddDllNoChange.h"
#include "importfun.h"
#include <tlhelp32.h>
extern SysCall g_SysCallIndex;;
AddDllNoChange::AddDllNoChange()
{
	InitSysCallIndex(&g_SysCallIndex);
	
}

AddDllNoChange::~AddDllNoChange()
{

}

ULONG AddDllNoChange::BBCastSectionProtection( IN ULONG characteristics, IN BOOLEAN noDEP )
{
    ULONG dwResult = PAGE_NOACCESS;

    if (characteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        dwResult = PAGE_NOACCESS;
    }
    else if (characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            dwResult = noDEP ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            dwResult = noDEP ? PAGE_READONLY : PAGE_EXECUTE_READ;
        else
            dwResult = noDEP ? PAGE_READONLY : PAGE_EXECUTE;
    }
    else
    {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            dwResult = PAGE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            dwResult = PAGE_READONLY;
        else
            dwResult = PAGE_NOACCESS;
    }

    return dwResult;
}
VOID AddDllNoChange::suspendAllThread(BOOL bsuspend)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	HANDLE hThread = 0;
	DWORD nCnt = 0;
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { sizeof(THREADENTRY32) };
		if (Thread32First(snapshot, &te))
		{
			DWORD pid = GetCurrentProcessId();
			bool first = true;
			do
			{
				if (te.th32OwnerProcessID == pid)
				{
					if (te.th32ThreadID != GetCurrentThreadId_()) 
					{
						nCnt = 0;
						hThread = 0;
						hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
						if (hThread)
						{
							if (bsuspend) 
							{
								nCnt = SuspendThread(hThread);

							}
							else 
							{

								nCnt = ResumeThread(hThread);
								if (nCnt != (DWORD)-1) 
								{
									for (int i = 1; i < nCnt; i++)
									{
										ResumeThread(hThread);
									}
								}
					
							}
							CloseHandle(hThread);
							
						}
					}

				}
			} while (Thread32Next(snapshot, &te));
		}
		CloseHandle(snapshot);
	}
}

DWORD AddDllNoChange::calcTextSize(MODULEINFO* pInfo,vector<sectionData>& pSectionData)
{

	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pInfo->lpBaseOfDll;
	pNtHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)pInfo->lpBaseOfDll + pDosHdr->e_lfanew);

	sectionData dwSection;
	DWORD nSize = 0;
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	if (IMAGE32(pNtHeaders))
		pFirstSection = (PIMAGE_SECTION_HEADER)((PIMAGE_NT_HEADERS32)pNtHeaders + 1);

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection;
		pSection < pFirstSection + pNtHeaders->FileHeader.NumberOfSections;
		pSection++)
	{
		if (IMAGE_SCN_MEM_EXECUTE & pSection->Characteristics)
		{
			nSize += pSection->Misc.VirtualSize;
		}
		else
		{
			dwSection.VirtualAddress = pSection->VirtualAddress;
			dwSection.VirtualSize = pSection->Misc.VirtualSize;
			dwSection.nProtection = BBCastSectionProtection(pSection->Characteristics, FALSE);
			pSectionData.emplace_back(dwSection);
		}
	}
	if (nSize > 0x10000) 
	{
		nSize = nSize & (~0xffff);
		nSize += 0x10000;
		if ((pSectionData.at(0).VirtualAddress+pSectionData.at(0).VirtualSize) >= nSize)
		{
			pSectionData.at(0).VirtualAddress = nSize;

			pSectionData.at(0).VirtualSize = pSectionData.at(1).VirtualAddress - pSectionData.at(0).VirtualAddress ;
		}
		else 
		{
			pSectionData.~vector();
		}
	}
	else 
	{
		nSize = 0;
	}

	return nSize;
}


BOOL __stdcall AddDllNoChange::AddNoChange(MODULEINFO* pInfo)
{
	BOOL bRet = FALSE;
	if (!pInfo) return bRet;

	HANDLE hSection = 0;
	LARGE_INTEGER cbSectionOffset = {};
	PVOID pViewBase = NULL;
	SIZE_T cbViewSize = 0;
	NTSTATUS ntstatus = 0;
	vector<sectionData> dwSectionData;

	ULONG nCanMapSize = 0;
	nCanMapSize = calcTextSize(pInfo,dwSectionData);
	if (nCanMapSize < 0x10000) {
		return bRet;
	}


	ULONG64 nNextMapAddress = nCanMapSize + (ULONG64)pInfo->lpBaseOfDll;
	ULONG nNextMapSize = pInfo->SizeOfImage - nCanMapSize;

	LARGE_INTEGER cbSectionSize = { 0 };
	cbSectionSize.QuadPart = pInfo->SizeOfImage;
	ntstatus = ZwCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&cbSectionSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);

	pViewBase = 0;
  
	cbSectionOffset.QuadPart = 0;
	cbViewSize = 0;
	ntstatus = ZwMapViewOfSection(
		hSection,
		NtCurrentProcess(),
		&pViewBase,
		0,
		0,
		&cbSectionOffset,
		&cbViewSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READWRITE);

	if (NT_SUCCESS(ntstatus)) 
	{
		RtlCopyMemory(pViewBase, pInfo->lpBaseOfDll, pInfo->SizeOfImage);
		//把内容写入section后,就把当前得 地址 卸载
		ntstatus = ZwUnmapViewOfSection(NtCurrentProcess(), pViewBase);


		ntstatus = ZwUnmapViewOfSection(NtCurrentProcess(), pInfo->lpBaseOfDll);
		if (NT_SUCCESS(ntstatus)) 
		{
			pViewBase = pInfo->lpBaseOfDll;
			cbSectionOffset.QuadPart = 0;
			cbViewSize = nCanMapSize;
			ntstatus = ZwMapViewOfSection(
				hSection,
				NtCurrentProcess(),
				&pViewBase,
				0,
				0,
				&cbSectionOffset,
				&cbViewSize,
				ViewUnmap,
				SEC_NO_CHANGE,
				PAGE_EXECUTE_READ);

			if (NT_SUCCESS(ntstatus)) 
			{
				pViewBase = (PVOID)nNextMapAddress;
				cbSectionOffset.QuadPart = nCanMapSize;
				cbViewSize = nNextMapSize;
				ntstatus = ZwMapViewOfSection(
					hSection,
					NtCurrentProcess(),
					&pViewBase,
					0,
					0,
					&cbSectionOffset,
					&cbViewSize,
					ViewUnmap,
					0,
					PAGE_READWRITE);

				
				if (NT_SUCCESS(ntstatus) && !dwSectionData.empty()) 
				{
					vector<sectionData> ::iterator it = dwSectionData.begin();

					SIZE_T tmpSize = 0;
					DWORD OldAccessProtection = 0;
					ULONG prot = 0;
					PVOID pAddr = NULL;
					for (it; it != dwSectionData.end(); ++it)
					{
						if (it->nProtection == PAGE_READONLY)
						{
							prot = it->nProtection;
							pAddr = (PVOID)((ULONG64)pInfo->lpBaseOfDll + it->VirtualAddress);
							tmpSize = it->VirtualSize;
							ZwProtectVirtualMemory(NtCurrentProcess(), &pAddr, &tmpSize, prot, &OldAccessProtection);
					
						}
					}

					

				}
				
			}
		}
	}

	if (hSection) {
		CloseHandle(hSection);
	}


	return bRet;
}


BOOL AddDllNoChange::EnterLock()
{
	suspendAllThread(TRUE);
	return TRUE;
}

BOOL AddDllNoChange::LeaveLock(VOID)
{
	suspendAllThread(FALSE);
	return TRUE;
}


