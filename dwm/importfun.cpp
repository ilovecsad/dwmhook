#include "importfun.h"
#include "ldasm.h"
#include <shlwapi.h>


EXTERN_C DWORD SysCallIndex = 0;

SysCall g_SysCallIndex;
DWORD get_zwfun_index(PVOID pDllBase,char* szName, BOOL bIs64)
{
	DWORD  _eax = 0;
	ldasm_data ld = { 0 };
	size_t len = 0;
	unsigned char* pEip = (unsigned char*)GetProcAddress((HMODULE)pDllBase, szName);

	if (!pEip)return 0;

	while (TRUE)
	{
		len = ldasm(pEip, &ld, bIs64);
		if (len == 5 && pEip[0] == 0xB8) // mov eax,xxxxxx
		{
			_eax = *(DWORD*)(&pEip[1]);
			break;
		}
		pEip += len;
	}


	return _eax;
}







//ULONG64 GetModuleHandle_(LPCWSTR lpModuleName ,PDWORD SizeOfImage)
//{
//	
//	PPEB peb = (PPEB)__readgsqword(0x60);
//	PPEB_LDR_DATA ldr = peb->Ldr;
//    if (ldr) 
//    {
//        PLDR_DATA_TABLE_ENTRY module = NULL;
//        PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
//        while (list != NULL && list != &ldr->InMemoryOrderModuleList)
//        {
//            module = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
//            if (module && module->DllBase)
//            {
//                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint64_t)module->DllBase + ((PIMAGE_DOS_HEADER)module->DllBase)->e_lfanew);
//                if (StrStrW(module->FullDllName.Buffer, lpModuleName))
//                {
//                    if (SizeOfImage)
//                    {
//                        *SizeOfImage = nt->OptionalHeader.SizeOfImage;
//                    }
//                    return (ULONG64)module->DllBase;
//                }
//            }
//            list = list->Flink;
//        }
//    }
//	return NULL;
//}
//
//ULONG64 GetProcAddress_(PVOID BaseAddress, char *lpFunctionName) 
//{
//
//    PIMAGE_DOS_HEADER       pDosHdr  = (PIMAGE_DOS_HEADER)BaseAddress;
//    PIMAGE_NT_HEADERS32     pNtHdr32 = NULL;
//    PIMAGE_NT_HEADERS64     pNtHdr64 = NULL;
//    PIMAGE_EXPORT_DIRECTORY pExport  = NULL;
//    ULONG                   expSize  = 0;
//    ULONG_PTR               pAddress = 0;
//    PUSHORT                 pAddressOfOrds;
//    PULONG                  pAddressOfNames;
//    PULONG                  pAddressOfFuncs;
//    ULONG                   i;
//
//    if (BaseAddress == NULL)
//        return 0;
//
//    /// Not a PE file
//    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
//        return 0;
//
//    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
//    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
//
//    // Not a PE file
//    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
//        return 0;
//
//    // 64 bit image
//    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
//        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
//                                                .VirtualAddress +
//                                            (ULONG_PTR)BaseAddress);
//        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    }
//    // 32 bit image
//    else {
//        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
//                                                .VirtualAddress +
//                                            (ULONG_PTR)BaseAddress);
//        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    }
//
//    pAddressOfOrds  = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
//    pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
//    pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);
//
//    for (i = 0; i < pExport->NumberOfFunctions; ++i) {
//        USHORT OrdIndex = 0xFFFF;
//        PCHAR  pName    = NULL;
//
//        // Find by index
//        if ((ULONG_PTR)lpFunctionName <= 0xFFFF) 
//		{
//            OrdIndex = (USHORT)i;
//        }
//        // Find by name
//        else if ((ULONG_PTR)lpFunctionName > 0xFFFF && i < pExport->NumberOfNames) {
//            pName    = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);
//            OrdIndex = pAddressOfOrds[i];
//        }
//        // Weird params
//        else
//            return 0;
//
//        if (((ULONG_PTR)lpFunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)lpFunctionName) == OrdIndex + pExport->Base) ||
//            ((ULONG_PTR)lpFunctionName > 0xFFFF && strcmp(pName, (char *)(PCTSTR)lpFunctionName) == 0)) {
//            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)BaseAddress;
//
//            // Check forwarded export
//            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize) {
//                return 0;
//            }
//
//            break;
//        }
//    }
//    return (ULONG_PTR)pAddress;
//}
VOID InitSysCallIndex(SysCall* pInfo)
{
    if (!pInfo || pInfo->ZwSuspendThread)return;
    PVOID h = (PVOID)GetModuleHandle(L"ntdll.dll");
 
    pInfo->ZwCreateSection = get_zwfun_index(h,"ZwCreateSection", TRUE);
    pInfo->ZwMapViewOfSection = get_zwfun_index(h,"ZwMapViewOfSection", TRUE);
    pInfo->ZwUnmapViewOfSection = get_zwfun_index(h,"ZwUnmapViewOfSection", TRUE);
    pInfo->ZwQueryVirtualMemory = get_zwfun_index(h,"ZwQueryVirtualMemory", TRUE);
    pInfo->ZwClose = get_zwfun_index(h,"ZwClose", TRUE);
    pInfo->ZwProtectVirtualMemory = get_zwfun_index(h,"ZwProtectVirtualMemory", TRUE);
    pInfo->ZwDelayExecution = get_zwfun_index(h,"ZwDelayExecution", TRUE);
    pInfo->ZwCreateThreadEx = get_zwfun_index(h, "ZwCreateThreadEx", TRUE);
    pInfo->ZwContinue = get_zwfun_index(h, "ZwContinue", TRUE);
    pInfo->ZwSetContextThread = get_zwfun_index(h, "ZwSetContextThread", TRUE);
    pInfo->ZwQuerySystemInformation = get_zwfun_index(h, "ZwQuerySystemInformation", TRUE);
    pInfo->ZwResumeThread = get_zwfun_index(h, "ZwResumeThread", TRUE);
    pInfo->ZwSuspendThread = get_zwfun_index(h, "ZwSuspendThread", TRUE);
    return VOID();
}


NTSTATUS ZwResumeThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL)
{
     SysCallIndex = g_SysCallIndex.ZwResumeThread;
     t_ZwResumeThread ZwResumeThread = (t_ZwResumeThread)shellSysCall64;

    return ZwResumeThread(ThreadHandle, PreviousSuspendCount);
}
NTSTATUS ZwSuspendThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL)
{
     SysCallIndex = g_SysCallIndex.ZwSuspendThread;
     t_ZwSuspendThread ZwSuspendThread = (t_ZwSuspendThread)shellSysCall64;

    return ZwSuspendThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS ZwCreateThreadEx(PVOID StartRoutine, PVOID StartContext)
{
     SysCallIndex = g_SysCallIndex.ZwCreateThreadEx;
    t_ZwCreateThreadEx ZwCreateThreadEx = (t_ZwCreateThreadEx)shellSysCall64;
    HANDLE hThreadHanle = NULL;
    //rcx rdx r8 r9 
    return ZwCreateThreadEx(&hThreadHanle,THREAD_ALL_ACCESS,NULL,(HANDLE)-1,(PTHREAD_START_ROUTINE)StartRoutine,StartContext,
        0,0,0,0,NULL);
}

NTSTATUS ZwDelayExecution(IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval)
{
    SysCallIndex = g_SysCallIndex.ZwDelayExecution;
    t_ZwDelayExecution ZwDelayExecution = (t_ZwDelayExecution)shellSysCall64;

    return ZwDelayExecution(Alertable, DelayInterval);
}

DWORD __stdcall ZwCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    SysCallIndex = g_SysCallIndex.ZwCreateSection;
    t_ZwCreateSection ZwCreateSection = (t_ZwCreateSection)shellSysCall64;

    return ZwCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

DWORD __stdcall ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
    SysCallIndex = g_SysCallIndex.ZwMapViewOfSection;
    t_ZwMapViewOfSection ZwMapViewOfSection = (t_ZwMapViewOfSection)shellSysCall64;
    return ZwMapViewOfSection(SectionHandle,ProcessHandle,BaseAddress,ZeroBits,CommitSize,SectionOffset,ViewSize,InheritDisposition,AllocationType,Win32Protect);
}

ULONG __stdcall ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    SysCallIndex = g_SysCallIndex.ZwUnmapViewOfSection;
    t_ZwUnmapViewOfSection ZwUnmapViewOfSection = (t_ZwUnmapViewOfSection)shellSysCall64;
    return ZwUnmapViewOfSection(ProcessHandle,BaseAddress);
}

NTSTATUS __stdcall ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
     SysCallIndex = g_SysCallIndex.ZwQueryVirtualMemory;
    t_ZwQueryVirtualMemory ZwQueryVirtualMemory = (t_ZwQueryVirtualMemory)shellSysCall64;
    return ZwQueryVirtualMemory(ProcessHandle,BaseAddress,MemoryInformationClass,MemoryInformation,MemoryInformationLength,ReturnLength);
}

NTSTATUS ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
     SysCallIndex = g_SysCallIndex.ZwQuerySystemInformation;
    t_ZwQuerySystemInformation ZwQuerySystemInformation = (t_ZwQuerySystemInformation)shellSysCall64;
    return ZwQuerySystemInformation(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);
}

NTSTATUS __stdcall ZwClose(HANDLE Handle)
{
    SysCallIndex = g_SysCallIndex.ZwClose;
    t_ZwClose ZwClose = (t_ZwClose)shellSysCall64;
    return ZwClose(Handle);
}

NTSTATUS NTAPI ZwProtectVirtualMemory(IN HANDLE     ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG     NewAccessProtection,
	OUT PULONG     OldAccessProtection
	)
{
    SysCallIndex = g_SysCallIndex.ZwProtectVirtualMemory;
    t_ZwProtectVirtualMemory ZwProtectVirtualMemory = (t_ZwProtectVirtualMemory)shellSysCall64;
    return ZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

DWORD __stdcall GetCurrentThreadId_(VOID)
{
    PTEB64 pTeb = (PTEB64)__readgsqword(0x30);
    return (DWORD)pTeb->ClientId.UniqueThread;
}

DWORD WINAPI GetCurrentProcessId_(VOID)
{
    PTEB64 pTeb = (PTEB64)__readgsqword(0x30);
    return (DWORD)pTeb->ClientId.UniqueProcess;
}





