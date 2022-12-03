#include "exceptionhook.h"
#include <TlHelp32.h>
#include "hde/hde64.h"
#include <intrin.h>
#include <cassert>

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define PAGE_WRITE_FLAGS \
(PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define SAVE_CODE 50


exceptionhook* g_exceptionhook;
ULONG_PTR KiUserExceptionDispatcher = NULL;
t_ZwContinue_ ZwContinue = NULL;


exceptionhook::exceptionhook(BOOL bHook)
{
	m_bHookKiDispatchException = bHook;
    RtlSecureZeroMemory(&m_hardWareArry, sizeof(m_hardWareArry));
    m_BreakPointList.clear();
	m_AceessViolationList.clear();
	if (m_bHookKiDispatchException) {
		HMODULE h = GetModuleHandleW(L"ntdll.dll");
		KiUserExceptionDispatcher = (ULONG_PTR)GetProcAddress(h, "KiUserExceptionDispatcher");
		ZwContinue = (t_ZwContinue_)GetProcAddress(h, "ZwContinue");
		if (KiUserExceptionDispatcher && ZwContinue)
		{
			m_VehHandler = SetWow64PrepareForException(Wow64PrepareForExceptionHook);
		}
	}
	else 
	{
		m_VehHandler = AddVectoredExceptionHandler(TRUE, VehHandler);
	}
	m_pAllcoateMemory = VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (m_VehHandler && m_pAllcoateMemory) 
	{
		m_Initialize = TRUE;
	}
	assert(m_VehHandler);
}

exceptionhook::~exceptionhook()
{
	DisableHardWare();
	DisableBreakPointHook();
	DisableAceessViolationHook();
	if (m_bHookKiDispatchException) 
	{
		SetWow64PrepareForException(0);
	}
	else {
		RemoveVectoredExceptionHandler(m_VehHandler);
	}
}


void exceptionhook::Wow64PrepareForExceptionHook(PEXCEPTION_RECORD er, PCONTEXT ctx)
{
	EXCEPTION_POINTERS ep = { er,ctx };
	if (VehHandler(&ep) == EXCEPTION_CONTINUE_EXECUTION)
	{
		ZwContinue(ctx, FALSE);
	}
}

void* exceptionhook::SetWow64PrepareForException(void* ptr)
{
	char* excdis = reinterpret_cast<char*>(KiUserExceptionDispatcher);
	int rel = *reinterpret_cast<int*>(excdis + 0x4);
	void** predis = reinterpret_cast<void**>(excdis + rel + 0x8);

	PVOID pBaseAddress = predis;

	DWORD protect = 0;
	if (VirtualProtect(pBaseAddress, 1, PAGE_READWRITE, &protect)) 
	{
		void* old_predis = *predis;
		*predis = ptr;
		VirtualProtect(pBaseAddress, 1, protect, &protect);
		return pBaseAddress;
	}
	return NULL;
}

PVOID exceptionhook::CreateOriginalShellcode(PVOID pTarget)
{
	if (!m_Initialize || m_CurrentHookSize > m_MaxHookSize || !pTarget ) return NULL;
	char shellcode[SAVE_CODE];
	RtlFillMemory(shellcode, SAVE_CODE, 0xcc);
	PVOID pAllocate = NULL;
	UCHAR code[] = { 
    0x50,        //push rax
    0x48,0xb8,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,//mov rax,xxx
    0x48,0x87,0x04,0x24, //xchg[rsp],rax
    0xc3 }; //ret
	hde64s hs;
	hde64_disasm(pTarget, &hs);
	if (hs.len)
	{
	     pAllocate = (PVOID)((ULONG_PTR)m_pAllcoateMemory + m_CurrentHookSize * SAVE_CODE);
	     *(PULONG64)&code[3] = ((ULONG64)pTarget + hs.len);
	     RtlCopyMemory(shellcode, pTarget, hs.len);
	     RtlCopyMemory(&shellcode[hs.len], code, sizeof(code));
	     RtlCopyMemory(pAllocate, shellcode, SAVE_CODE);
		 InterlockedAdd(&m_CurrentHookSize, 1);
	}
	return pAllocate;
}

BOOL __stdcall exceptionhook::CreateHardWare(LPVOID pTarget, BreakType nType, ExceptionCallBack pCallBack, BreakLength nLength)
{
	BOOL nRet = FALSE;


	if (!m_Initialize || m_nHardWareCurrentCnt > m_nHardWareMaxCnt || !pTarget || !pCallBack) return nRet;

	m_hardWareArry.nData[m_nHardWareCurrentCnt].pTarget = pTarget;
	m_hardWareArry.nData[m_nHardWareCurrentCnt].nType = nType;
	m_hardWareArry.nData[m_nHardWareCurrentCnt].nLength = nLength;
	m_hardWareArry.nData[m_nHardWareCurrentCnt].pCallBack = pCallBack;
	m_nHardWareCurrentCnt++;
	nRet = TRUE;


    return nRet;
}

BOOL exceptionhook::EnableHardWare()
{
	HANDLE hThread = 0;
	BOOL bRet = FALSE;
	CONTEXT ct;
	DR7 nDr7;


	if (!SetDr7AndThreadContext(&nDr7, &ct))return bRet;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { sizeof(THREADENTRY32) };
		if (Thread32First(snapshot, &te))
		{
			DWORD pid = GetCurrentProcessId();

			do
			{
				if (te.th32OwnerProcessID == pid)
				{

					if (te.th32ThreadID != GetCurrentThreadId())
					{
						hThread = 0;
						hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT , FALSE, te.th32ThreadID);
						if (hThread)
						{
							if ((DWORD)-1 != SuspendThread(hThread))
							{
								ct.Dr7 |= nDr7.all;
								bRet = SetThreadContext(hThread, &ct);
								
								ResumeThread(hThread);
			
							}
							CloseHandle(hThread);
						}
					}

				}
			} while (Thread32Next(snapshot, &te));
		}
		CloseHandle(snapshot);
	}
	
	return bRet;

}

VOID exceptionhook::DisableHardWare(int DRn)
{
	HANDLE hThread = 0;
	BOOL bRet = FALSE;
	CONTEXT ct;
	RtlSecureZeroMemory(&ct, sizeof(CONTEXT));

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (DRn != -1) 
	{

		switch (DRn)
		{
		case 0:
		{
			m_hardWareArry.nDr0 = 0;
			m_hardWareArry.nDr7.fields.l0 = 0;
			break;
		}
		case 1:
		{
			m_hardWareArry.nDr1 = 0;
			m_hardWareArry.nDr7.fields.l1 = 0;
			break;
		}
		case 2:
		{
			m_hardWareArry.nDr2 = 0;
			m_hardWareArry.nDr7.fields.l2 = 0;
			break;
		}
		case 3:
		{
			m_hardWareArry.nDr3 = 0;
			m_hardWareArry.nDr7.fields.l3 = 0;
			break;
		}
		default:
			break;
		}
		ct.Dr7 = m_hardWareArry.nDr7.all;
		ct.Dr0 = m_hardWareArry.nDr0;
		ct.Dr1 = m_hardWareArry.nDr1;
		ct.Dr2 = m_hardWareArry.nDr2;
		ct.Dr3 = m_hardWareArry.nDr3;

	}
	else 
	{
		ct.Dr7 = 0;
		m_hardWareArry.nDr7.all = 0;
	}
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { sizeof(THREADENTRY32) };
		if (Thread32First(snapshot, &te))
		{
			do
			{
				if (te.th32OwnerProcessID ==  GetCurrentProcessId())
				{

					if (te.th32ThreadID != GetCurrentThreadId())
					{
						hThread = 0;
						hThread = OpenThread(THREAD_SUSPEND_RESUME|THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
						if (hThread)
						{
							if ((DWORD)-1 != SuspendThread(hThread))
							{
								bRet = SetThreadContext(hThread, &ct);
								
								ResumeThread(hThread);
							}
							CloseHandle(hThread);
						}
					}

				}
			} while (Thread32Next(snapshot, &te));
		}
		CloseHandle(snapshot);
	}

	return ;
}

BOOL __stdcall exceptionhook::CreateBreakPointException(LPVOID pTarget, ExceptionCallBack pCallBack,BOOL bDefault)
{
	BOOL bRet = FALSE;
	if (!pTarget || !pCallBack)return bRet;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	BreakPointData data = { 0 };
	if (VirtualQuery(pTarget, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
	{
		if (mbi.AllocationProtect & PAGE_EXECUTE_FLAGS)
		{
			hde64s hs;
	 	    hde64_disasm(pTarget, &hs);
			if (hs.len)
			{
				data.pDefaultFunc = CreateOriginalShellcode(pTarget);
				if (data.pDefaultFunc) 
				{
					data.AllocationProtect = mbi.AllocationProtect;
					RtlCopyMemory(&data.orgCode, pTarget, sizeof(data.orgCode));
					data.bEnable = FALSE;
					data.pTarget = pTarget;
					data.pCallBack = pCallBack;
					data.bDefault = bDefault;
					m_BreakPointList.push_back(data);
					bRet = TRUE;
				}
			}
		}
	}


	return bRet;
}

BOOL exceptionhook::EnableBreakPointHook(LPVOID pTarget)
{
	BOOL bRet = FALSE;

	std::list<BreakPointData> ::iterator it = m_BreakPointList.begin();

	if (pTarget) {
		for (it; it != m_BreakPointList.end(); ++it)
		{
			if (it->pTarget == pTarget && !it->bEnable)
			{
				if (it->AllocationProtect & PAGE_WRITE_FLAGS) 
				{
					it->bEnable = CreateInt3(pTarget, it->AllocationProtect);
					bRet = TRUE;
				}
				break;
			}
		}
	}
	else 
	{
				
		for (it; it != m_BreakPointList.end(); ++it)
		{
			if (it->AllocationProtect & PAGE_WRITE_FLAGS) {
				if (!it->bEnable) {
					it->bEnable = CreateInt3(it->pTarget, it->AllocationProtect);
					bRet = TRUE;
				}
			}
		}
	}
	return bRet;
}

VOID exceptionhook::DisableBreakPointHook(LPVOID pTarget)
{

	std::list<BreakPointData> ::iterator it = m_BreakPointList.begin();
	DWORD n = 0;
	if (pTarget) {
		for (it; it != m_BreakPointList.end(); ++it)
		{
			if (it->pTarget == pTarget && it->bEnable)
			{
			   if (it->AllocationProtect & PAGE_WRITE_FLAGS) {
				   if (VirtualProtect(pTarget, 1, it->AllocationProtect, &n))
				   {
					   RtlCopyMemory(pTarget, it->orgCode, sizeof(it->orgCode));
					   it->bEnable = !VirtualProtect(pTarget, 1, n, &n);
				   }
			   }
			   break;
			}
		}
	}
	else 
	{
				
		for (it; it != m_BreakPointList.end(); ++it)
		{
			if (it->pTarget && it->bEnable) 
			{
				it->bEnable = FALSE;
				if (it->AllocationProtect & PAGE_WRITE_FLAGS) {
					if (VirtualProtect(it->pTarget, 1, it->AllocationProtect, &n))
					{
						RtlCopyMemory(it->pTarget, it->orgCode, sizeof(it->orgCode));
						it->bEnable = !VirtualProtect(it->pTarget, 1, n, &n);
					}
				}
			}
		}
	}

	return;
}

BOOL __stdcall exceptionhook::CreateAceessViolationException(LPVOID pTarget, ExceptionCallBack pCallBack)
{
	BOOL bRet = FALSE;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	AceessViolationData nData = { 0 };

	if (VirtualQuery(pTarget, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
	{
		if (mbi.Protect & PAGE_EXECUTE_FLAGS) {
			nData.pTarget = pTarget;
			nData.AllocationProtect = mbi.AllocationProtect;
			nData.nOrgProtect = mbi.Protect;
			nData.SetNewProtect = PAGE_READONLY;
			nData.bEnable = FALSE;
			nData.pTargetBase = (PVOID)((ULONG_PTR)pTarget & ~0xfff);
			nData.pTargetEnd = (PVOID)((ULONG_PTR)nData.pTargetBase + 0x1000);
			nData.pCallBack = pCallBack;
			m_AceessViolationList.push_back(nData);
			bRet = TRUE;
			m_bSetAceessViolation = TRUE;
		}
	}

	return bRet;
}

BOOL exceptionhook::EnableAceessViolationHook(LPVOID pTarget)
{
	BOOL bRet = FALSE;

	DWORD n = 0;
	std::list<AceessViolationData> ::iterator it = m_AceessViolationList.begin();
	if (pTarget) {
		for (it; it != m_AceessViolationList.end(); ++it)
		{
			if (it->pTarget == pTarget)
			{
				it->bEnable = VirtualProtect(it->pTarget, 1, it->SetNewProtect, &n);
				break;
			}
		}
	}
	else
	{
		for (it; it != m_AceessViolationList.end(); ++it)
		{
			if (it->pTarget)
			{
				it->bEnable = VirtualProtect(it->pTarget, 1, it->SetNewProtect, &n);
			}
		}
	}

	
	return bRet;
}

VOID exceptionhook::DisableAceessViolationHook(LPVOID pTarget)
{
	BOOL bRet = FALSE;

	DWORD n = 0;
	std::list<AceessViolationData> ::iterator it = m_AceessViolationList.begin();
	if (pTarget) {
		for (it; it != m_AceessViolationList.end(); ++it)
		{
			if (it->pTarget == pTarget)
			{
				it->bEnable = !VirtualProtect(it->pTarget, 1, it->nOrgProtect, &n);
				break;
			}
		}
	}
	else
	{
		for (it; it != m_AceessViolationList.end(); ++it)
		{
			if (it->pTarget)
			{
				it->bEnable = !VirtualProtect(it->pTarget, 1, it->nOrgProtect, &n);
			}
		}
	}


	return ;
}

BOOL exceptionhook::CreateJmpSpringBoard(LPVOID pTarget, LPVOID pDetour,LPVOID* ppRip,LPVOID* ppOriginal,int nOffset)
{
	BOOL bRet = FALSE;
	if (!m_Initialize || m_CurrentHookSize > m_MaxHookSize || !pTarget ) return bRet;
	char shellcode[SAVE_CODE];
	RtlFillMemory(shellcode, SAVE_CODE, 0xcc);
	PVOID pAllocate = NULL;
	UCHAR code[] = { 
    0x50,        //push rax
    0x48,0xb8,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,//mov rax,xxx
    0x48,0x87,0x04,0x24, //xchg[rsp],rax
    0xc3 }; //ret
	UCHAR jmppDetourCode[] = { 
    0x50,        //push rax
    0x48,0xb8,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,//mov rax,xxx
    0x48,0x87,0x04,0x24, //xchg[rsp],rax
    0xc3 }; //ret

	int len = 0;
	int nTemplen = nOffset;
	hde64s hs;
	RtlSecureZeroMemory(&hs, sizeof(hde64s));
	hde64_disasm(pTarget, &hs);
	if (hs.len)
	{
	     pAllocate = (PVOID)((ULONG_PTR)m_pAllcoateMemory + m_CurrentHookSize * SAVE_CODE);
		 *(PULONG64)&jmppDetourCode[3] = ((ULONG64)pDetour);
		 RtlCopyMemory(shellcode, jmppDetourCode, sizeof(jmppDetourCode));


		 if (nTemplen) {
			  ULONG_PTR nEip = 0;
			  nEip = (ULONG_PTR)pTarget;
			  while (len < nTemplen)
              {
                  RtlSecureZeroMemory(&hs, sizeof(hde64s));
                  hde64_disasm((PVOID)nEip, &hs);
				  if (!hs.len) {
					  return bRet;
				  }
				  len += hs.len;
                  nEip = (ULONG_PTR)pTarget;
                  nEip += len;
              }
		 }
		 else {
			 len = hs.len;
		 }

		 *(PULONG64)&code[3] = ((ULONG64)pTarget + len);
	     RtlCopyMemory(&shellcode[sizeof(jmppDetourCode)], pTarget, len);
		 RtlCopyMemory(&shellcode[len + sizeof(jmppDetourCode)], code, sizeof(code));
	     RtlCopyMemory(pAllocate, shellcode, SAVE_CODE);
		 InterlockedAdd(&m_CurrentHookSize, 1);
		 if (ppOriginal)
		 {
			 *ppOriginal = (PVOID)((ULONG_PTR)pAllocate + sizeof(jmppDetourCode));
		 }
		 if (ppRip)
		 {
			 *ppRip = pAllocate;
		 }
		 bRet = TRUE;
	}
	return bRet;
}

BOOL exceptionhook::CreateCallSpringBoard(LPVOID pTarget, LPVOID pDetour,LPVOID* ppRip,LPVOID* ppOriginal,int nOffset)
{
#define Detour_Offset 41
	BOOL bRet = FALSE;
	if (!m_Initialize || m_CurrentHookSize > m_MaxHookSize || !pTarget ) return bRet;
	char shellcode[SAVE_CODE];
	RtlFillMemory(shellcode, SAVE_CODE, 0xcc);
	PVOID pAllocate = NULL;
	UCHAR code[] = { 
    0x50,        //push rax
    0x48,0xb8,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,//mov rax,xxx
    0x48,0x87,0x04,0x24, //xchg[rsp],rax
    0xc3 }; //ret
	UCHAR jmppDetourCode[] = {
    0xff,0x15,0,0,0,0
	}; //ret

	int len = 0;
	int nTemplen = nOffset;
	hde64s hs;
	RtlSecureZeroMemory(&hs, sizeof(hde64s));
	hde64_disasm(pTarget, &hs);
	if (hs.len)
	{
	     pAllocate = (PVOID)((ULONG_PTR)m_pAllcoateMemory + m_CurrentHookSize * SAVE_CODE);
		 *(PULONG)&jmppDetourCode[2] = Detour_Offset - sizeof(jmppDetourCode);
		 *(PULONG64)&shellcode[Detour_Offset] = (ULONG64)pDetour;
		 RtlCopyMemory(shellcode, jmppDetourCode, sizeof(jmppDetourCode));


		 if (nTemplen) {
			  ULONG_PTR nEip = 0;
			  nEip = (ULONG_PTR)pTarget;
			  while (len < nTemplen)
              {
                  RtlSecureZeroMemory(&hs, sizeof(hde64s));
                  hde64_disasm((PVOID)nEip, &hs);
				  if (!hs.len) {
					  return bRet;
				  }
				  len += hs.len;
                  nEip = (ULONG_PTR)pTarget;
                  nEip += len;
              }



		 }
		 else {
			 len = hs.len;
		 }

		 *(PULONG64)&code[3] = ((ULONG64)pTarget + len);
	     RtlCopyMemory(&shellcode[sizeof(jmppDetourCode)], (PVOID)((ULONG_PTR)pTarget+5), len);
		 RtlCopyMemory(&shellcode[len + sizeof(jmppDetourCode)], code, sizeof(code));
	     RtlCopyMemory(pAllocate, shellcode, SAVE_CODE);
		 InterlockedAdd(&m_CurrentHookSize, 1);
		 if (ppOriginal)
		 {
			 *ppOriginal = (PVOID)((ULONG_PTR)pAllocate + sizeof(jmppDetourCode));
		 }
		 if (ppRip)
		 {
			 *ppRip = pAllocate;
		 }
		 bRet = TRUE;
	}
	return bRet;
}


BOOL exceptionhook::GetHardWareExceptionStruct(EXCEPTION_POINTERS* pExceptionInfo, SingleData* pes)
{
	BOOL bRet = FALSE;
	if (!pExceptionInfo || !pes)return bRet;
	DR6 dr6;
	dr6.all = 0;
	dr6.all = pExceptionInfo->ContextRecord->Dr6;
	if (dr6.fields.BS){
		//单步异常
		return bRet;
	}
	RtlSecureZeroMemory(pes, sizeof(SingleData));
	int i = -1;
	//dr0
	if (dr6.fields.B0)
	{
		i = 0;
	}
	//dr1
	if (dr6.fields.B1)
	{
		i = 1;
	}
	//dr2
	if (dr6.fields.B2)
	{
		i = 2;
	}
	//dr3
	if (dr6.fields.B3)
	{
		i = 3;
	}


	if (i != -1)
	{
	
		RtlCopyMemory(pes, &g_exceptionhook->m_hardWareArry.nData[i], sizeof(SingleData));

		//重设 异常
		pExceptionInfo->ContextRecord->Dr0 = g_exceptionhook->m_hardWareArry.nDr0;
		pExceptionInfo->ContextRecord->Dr1 = g_exceptionhook->m_hardWareArry.nDr1;
		pExceptionInfo->ContextRecord->Dr2 = g_exceptionhook->m_hardWareArry.nDr2;
		pExceptionInfo->ContextRecord->Dr3 = g_exceptionhook->m_hardWareArry.nDr3;
		pExceptionInfo->ContextRecord->Dr7 = g_exceptionhook->m_hardWareArry.nDr7.all;

		bRet = TRUE;

	}

	return bRet;
}

BOOL exceptionhook::GetBreakPointData(PVOID nExceptionAddress, BreakPointData* pData)
{
	BOOL bRet = FALSE;
	if (!pData || !nExceptionAddress)return bRet;
	std::list<BreakPointData> ::iterator it = g_exceptionhook->m_BreakPointList.begin();
	for (it; it != g_exceptionhook->m_BreakPointList.end(); ++it)
	{
	    if (it->pTarget && it->pTarget == nExceptionAddress)
	    {
	    
	         pData->pCallBack = it->pCallBack;
	         pData->pDefaultFunc = it->pDefaultFunc;
	         pData->bEnable = it->bEnable;
			 pData->pCallBack = it->pCallBack;
			 pData->bDefault = it->bDefault;
			 bRet = TRUE;
	         break;
	    }
	}


	return bRet;
}

BOOL exceptionhook::GetAceessViolationData(PVOID nExceptionAddress,AceessViolationData* pData)
{
	BOOL bRet = FALSE;
	std::list<AceessViolationData> ::iterator it = g_exceptionhook->m_AceessViolationList.begin();
	for (it; it != g_exceptionhook->m_AceessViolationList.end(); ++it)
	{
		 if ((it->pTargetBase <= (PVOID)nExceptionAddress) && (it->pTargetEnd > (PVOID)nExceptionAddress))
		 {
			 pData->AllocationProtect = it->AllocationProtect;
			 pData->bEnable = it->bEnable;
			 pData->SetNewProtect = it->SetNewProtect;
			 pData->nOrgProtect = it->nOrgProtect;
			 pData->pTarget = it->pTarget;
			 pData->pTargetBase = it->pTargetBase;
			 pData->pTargetEnd = it->pTargetEnd;
			 pData->pCallBack = it->pCallBack;
			 bRet = TRUE;

			 break;
		 }
	}

	return bRet;
}

BOOL exceptionhook::SetDr7AndThreadContext(DR7* pDr7, CONTEXT* pct)
{
	BOOL bRet = FALSE;
	if (!pDr7 || !pct)return bRet;
	pDr7->all = 0;
	pDr7->fields.reserved1 = 1;
	RtlSecureZeroMemory(pct, sizeof(CONTEXT));
	pct->ContextFlags = CONTEXT_DEBUG_REGISTERS;



	if (m_hardWareArry.nData[0].pTarget)
	{
		pct->Dr0 = (ULONG_PTR)m_hardWareArry.nData[0].pTarget;
		pDr7->fields.l0 = 1;
		pDr7->fields.len0 = m_hardWareArry.nData[0].nLength;
		pDr7->fields.rw0 = m_hardWareArry.nData[0].nType;
		m_hardWareArry.nDr0 = (ULONG_PTR)m_hardWareArry.nData[0].pTarget;
		bRet = TRUE;
	}
	if (m_hardWareArry.nData[1].pTarget) {
		pct->Dr1 = (ULONG_PTR)m_hardWareArry.nData[1].pTarget;
		pDr7->fields.l1 = 1;
		pDr7->fields.len1 = m_hardWareArry.nData[1].nLength;
		pDr7->fields.rw1 = m_hardWareArry.nData[1].nType;
		m_hardWareArry.nDr1 = (ULONG_PTR)m_hardWareArry.nData[1].pTarget;
		bRet = TRUE;
	}
	if (m_hardWareArry.nData[2].pTarget) {
		pct->Dr2 = (ULONG_PTR)m_hardWareArry.nData[2].pTarget;
		pDr7->fields.l2 = 1;
		pDr7->fields.len2 = m_hardWareArry.nData[2].nLength;
		pDr7->fields.rw2 = m_hardWareArry.nData[2].nType;
		m_hardWareArry.nDr2 = (ULONG_PTR)m_hardWareArry.nData[2].pTarget;
		bRet = TRUE;
	}
	if (m_hardWareArry.nData[3].pTarget)
	{
		pct->Dr3 = (ULONG_PTR)m_hardWareArry.nData[3].pTarget;
		pDr7->fields.l3 = 1;
		pDr7->fields.len3 = m_hardWareArry.nData[3].nLength;
		pDr7->fields.rw3 = m_hardWareArry.nData[3].nType;
		m_hardWareArry.nDr3 = (ULONG_PTR)m_hardWareArry.nData[3].pTarget;
		bRet = TRUE;
	}
	m_hardWareArry.nDr7.all = pDr7->all;


	return bRet;
}

BOOL exceptionhook::CreateInt3(LPVOID pTarget, DWORD AllocationProtect)
{
	BOOL bRet = FALSE;
	char sz = 0xcc;
	DWORD n = 0;
	if (VirtualProtect(pTarget, 1, AllocationProtect, &n))
	{
		RtlCopyMemory(pTarget,&sz, 1);

		bRet = VirtualProtect(pTarget, 1, n, &n);
	}

	return bRet;
}




LONG __stdcall exceptionhook::VehHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	LONG result = EXCEPTION_CONTINUE_SEARCH;
	ULONG_PTR dwExceptionAddress = 0;
 #ifdef _WIN64
	dwExceptionAddress = (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress;	
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		 BOOL bExceute = FALSE;
		 DR6 dr6;
	     eflags eflags;
		 SingleData data = { 0 };

	     eflags.all = pExceptionInfo->ContextRecord->EFlags;
		 dr6.all = pExceptionInfo->ContextRecord->Dr6;
		 eflags.fields.RF = 1;
		 pExceptionInfo->ContextRecord->EFlags = eflags.all;
		 if (GetHardWareExceptionStruct(pExceptionInfo, &data))
		 {
			 switch (data.nType)
			 {
			 case BreakOnExecute: //执行断点
			 {
				 if (data.pCallBack)
				 {
					 data.pCallBack(pExceptionInfo);
				 }
				 bExceute = TRUE;
				 break;
			 }
			 case BreakOnWrite://写入断点
			 {
				 //执行回调函数 
				 if (data.pCallBack)
				 {
					 data.pCallBack(pExceptionInfo);
				 }
				 bExceute = TRUE;
				 break;
			 }
			 case BreakOnAccess://访问断点
			 {
				 //执行回调函数 
				 if (data.pCallBack)
				 {
					 data.pCallBack(pExceptionInfo);
				 }
				 bExceute = TRUE;
				 break;
			 }
			 default:
				 break;
			 }
			 if (bExceute)
			 {

				 result = EXCEPTION_CONTINUE_EXECUTION;
			 }
		 }
		 else
		 {
			 ////默认是单步异常 单步步入 遇到call 和
			 if (g_exceptionhook->m_bSetAceessViolation) {
				 DWORD n = 0;
				 std::list<AceessViolationData> ::iterator it = g_exceptionhook->m_AceessViolationList.begin();
				 for (it; it != g_exceptionhook->m_AceessViolationList.end(); ++it)
				 {
					 VirtualProtect(it->pTargetBase, 1, it->SetNewProtect, &n);
				 }


				 result = EXCEPTION_CONTINUE_EXECUTION;
			 }
		 }
	


	}
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
	{
		 BreakPointData nData = { 0 };
		if (GetBreakPointData((PVOID)dwExceptionAddress,&nData))
		{
			if (nData.pCallBack)
			{
				nData.pCallBack(pExceptionInfo);
			}
			if (nData.bDefault)
			{
				pExceptionInfo->ContextRecord->Rip = (ULONG_PTR)nData.pDefaultFunc;
			}


			result = EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		 AceessViolationData nData = { 0 };
		if (GetAceessViolationData((PVOID)dwExceptionAddress, &nData))
		{

			DWORD n = 0;
			VirtualProtect(nData.pTarget, 1, nData.nOrgProtect, &n);
			if (nData.pCallBack && (PVOID)dwExceptionAddress == nData.pTarget) {
				nData.pCallBack(pExceptionInfo);
			}

			pExceptionInfo->ContextRecord->EFlags |= 0x100;

			//处理这个 内存异常

			result = EXCEPTION_CONTINUE_EXECUTION;
		}
	}

#else
	 dwExceptionAddress = (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress;	
#endif



	return result;
}

