#include "hook.h"
#include "ldasm.h"
#include "hde/hde64.h"
extern SysCall g_SysCallIndex;
hook::hook()
{
    Initialize();
}

hook::~hook()
{
    Uninitialize();
}

BOOL __stdcall hook::CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{
    BOOL bRet = FALSE;
    if (!m_Initialize || m_CurrentHookSize > m_MaxHookSize || !pTarget || !pDetour)return bRet;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T nRetLength = 0;
    EnterSpinLock();

    m_hookStruct[m_CurrentHookSize].pTarget = pTarget;
    m_hookStruct[m_CurrentHookSize].pDetour = pDetour;
    if (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), m_hookStruct[m_CurrentHookSize].pTarget, MemoryBasicInformation, &mbi, sizeof(mbi), &nRetLength)))
    {
        if (mbi.AllocationProtect & PAGE_EXECUTE_FLAGS) 
        {
            m_hookStruct[m_CurrentHookSize].AllocationProtect = mbi.AllocationProtect;
            char hookCode[] = { 0x68,0x90,0x90,0x90,0x90,0xc3 };
            UCHAR shellcode[SAVE_CODE];
            PVOID pAllocate = NULL;
            PVOID pAllocate2 = NULL;

            if (pTarget && pDetour)
            {
                memset(shellcode, 0x90, SAVE_CODE);
                pAllocate = (PVOID)((ULONG_PTR)m_pAllcoateMemory + m_CurrentHookSize * SAVE_CODE);
                pAllocate2 = (PVOID)((ULONG_PTR)m_AllcoateMemoryNoChange + m_CurrentHookSize * SAVE_CODE);
                DWORD len = 0;

                ldasm_data ld;
                ULONG_PTR nEip = 0;
                nEip = (ULONG_PTR)pTarget;
                while (len < sizeof(hookCode) && nEip)
                {
                    RtlSecureZeroMemory(&ld, sizeof(ldasm_data));
                    len += ldasm((char*)nEip, &ld, TRUE);
                    nEip = (ULONG_PTR)pTarget;
                    nEip += len;
                }
                if (len >= sizeof(hookCode))
                {
                    //记录一下原始硬编码得长度 方便还原
                    m_hookStruct[m_CurrentHookSize].nOrgLen = len;

                    //求出 跳板得hook shellcode
                    memcpy(&hookCode[1], &pAllocate2, sizeof(ULONG));
                    memcpy(&m_hookStruct[m_CurrentHookSize].hookCode, hookCode, sizeof(hookCode));

                    //求出 跳板得shellcode
                    UCHAR code[] = { 
                    0x50,        //push rax
                    0x48,0xb8,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,//mov rax,xxx
                    0x48,0x87,0x04,0x24, //xchg[rsp],rax
                    0xc3 }; //ret
                    
                    *(PULONG64)&code[3] = (ULONG64)pDetour;
                    m_hookStruct[m_CurrentHookSize].orgCodePos = sizeof(code);

                    memcpy(shellcode, code, sizeof(code));
                    memcpy(&shellcode[sizeof(code)], pTarget, len);
                    len += sizeof(code);
                    shellcode[len] = 0xff;
                    shellcode[len+1] = 0x25;
                    *(PULONG)&shellcode[len + 2] = 0;
                    memcpy(&shellcode[len+6], &nEip, sizeof(ULONG_PTR));
                    memcpy(&m_hookStruct[m_CurrentHookSize].orgCode, shellcode, sizeof(shellcode));
                    
                    memcpy(pAllocate, &m_hookStruct[m_CurrentHookSize].orgCode, sizeof(shellcode));
                    
                    m_hookStruct[m_CurrentHookSize].bSucceedHook = FALSE;
                    
                    if (ppOriginal)
                    {
                        *ppOriginal = (PVOID)((ULONG64)pAllocate2 + sizeof(code));
                        m_hookStruct[m_CurrentHookSize].pOriginal = (PVOID)((ULONG64)pAllocate2 + sizeof(code));
                    }
         
                    m_CurrentHookSize++;
                    bRet = TRUE;
                }
            }
        }
    }
     LeaveSpinLock();


    return bRet;
}

BOOL __stdcall hook::CreateCallHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{

    	// [ E8 ? ? ? ? ] the relative addr will be converted to absolute addr
	auto ResolveCall = [](DWORD_PTR sig)
	{
		return sig = sig + *reinterpret_cast<int*>(sig + 1) + 5;
	};

	//
	// [ 48 8D 05 ? ? ? ? ] the relative addr will be converted to absolute addr
	auto ResolveRelative = [](DWORD_PTR sig)
	{
		return sig = sig + *reinterpret_cast<int*>(sig + 0x3) + 0x7;
	};

#define Detour_Offset 41
    BOOL bRet = FALSE;
    if (!m_Initialize || m_CurrentHookSize > m_MaxHookSize || !pTarget || !pDetour)return bRet;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T nRetLength = 0;
    EnterSpinLock();

    m_hookStruct[m_CurrentHookSize].pTarget = pTarget;
    m_hookStruct[m_CurrentHookSize].pDetour = pDetour;
    if (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), m_hookStruct[m_CurrentHookSize].pTarget, MemoryBasicInformation, &mbi, sizeof(mbi), &nRetLength)))
    {
        if (mbi.AllocationProtect & PAGE_EXECUTE_FLAGS) 
        {
            m_hookStruct[m_CurrentHookSize].AllocationProtect = mbi.AllocationProtect;
            char hookCode[] = { 0x68,0x90,0x90,0x90,0x90,0xc3 };
            UCHAR shellcode[SAVE_CODE];
            PVOID pAllocate = NULL;
            PVOID pAllocate2 = NULL;

            if (pTarget && pDetour)
            {
                memset(shellcode, 0x90, SAVE_CODE);
                pAllocate = (PVOID)((ULONG_PTR)m_pAllcoateMemory + m_CurrentHookSize * SAVE_CODE);
                pAllocate2 = (PVOID)((ULONG_PTR)m_AllcoateMemoryNoChange + m_CurrentHookSize * SAVE_CODE);
                DWORD nTempLen = 0;
                DWORD len = 0;
             
                ldasm_data ld;
                ULONG_PTR nEip = 0;
                nEip = (ULONG_PTR)pTarget;
                while (len < sizeof(hookCode) && nEip)
                {
                    RtlSecureZeroMemory(&ld, sizeof(ldasm_data));
                    len += ldasm((char*)nEip, &ld, TRUE);
                    nEip = (ULONG_PTR)pTarget;
                    nEip += len;
                }
                if (len >= sizeof(hookCode))
                {
                    //记录一下原始硬编码得长度 方便还原
                    m_hookStruct[m_CurrentHookSize].nOrgLen = len;

                    //求出 跳板得hook shellcode
                    memcpy(&hookCode[1], &pAllocate2, sizeof(ULONG));
                    memcpy(&m_hookStruct[m_CurrentHookSize].hookCode, hookCode, sizeof(hookCode));

                    //求出 跳板得shellcode
                    UCHAR code[] = { 
                    0xff,0x15,0,0,0,0,        //push rax
                    }; //pop rax
                    
                    *(PULONG)&code[2] = Detour_Offset - sizeof(code);
                   
                    RtlSecureZeroMemory(&ld, sizeof(ldasm_data));
                    nTempLen = ldasm((char*)pTarget, &ld, TRUE);
                    memcpy(shellcode, code, sizeof(code));
                    len -= nTempLen; //跳过call xxxx 这行汇编
                    *(PULONG64)&shellcode[Detour_Offset] = (ULONG64)pDetour;


                    memcpy(&shellcode[sizeof(code)], (PVOID)((ULONG_PTR)pTarget + nTempLen), len);
                    len += sizeof(code);
             
                    //构造跳转 jmp xxxxxx
                    shellcode[len] = 0xff;
                    shellcode[len+1] = 0x25;
                    *(PULONG)&shellcode[len + 2] = 0;
                    memcpy(&shellcode[len+6], &nEip, sizeof(ULONG_PTR));

                
                    nTempLen = len + 6 + 8;
                    m_hookStruct[m_CurrentHookSize].orgCodePos = nTempLen;
                    if (nTempLen < Detour_Offset)
                    {
                        memcpy(&shellcode[nTempLen], pTarget, m_hookStruct[m_CurrentHookSize].nOrgLen);
                        memcpy(&m_hookStruct[m_CurrentHookSize].orgCode, shellcode, sizeof(shellcode));
                        memcpy(pAllocate, &m_hookStruct[m_CurrentHookSize].orgCode, sizeof(shellcode));

                        m_hookStruct[m_CurrentHookSize].bSucceedHook = FALSE;
                        m_hookStruct[m_CurrentHookSize].pOriginal = (PVOID)((ULONG64)pAllocate2 + sizeof(code));
                        if (ppOriginal)
                        {
                            DWORD_PTR n = ResolveCall((DWORD_PTR)pTarget);
                            m_hookStruct[m_CurrentHookSize].pOriginal = (PVOID)n;
                            *ppOriginal = m_hookStruct[m_CurrentHookSize].pOriginal;
                          
                        }

                        m_CurrentHookSize++;
                        bRet = TRUE;
                    }
                }
            }
        }
    }
    LeaveSpinLock();


    return bRet;
}

BOOL __stdcall hook::EnableHook(PVOID pTarget)
{
    BOOL bRet = FALSE;
    if (!m_Initialize)return bRet;

    EnterSpinLock();

    for (int i = 0; i < m_CurrentHookSize; i++)
    {
        if (!pTarget) {
            if (!m_hookStruct[i].bSucceedHook)
            {
                SIZE_T nSize = 1;
                PVOID nBaseAddress = m_hookStruct[i].pTarget;
                DWORD oldProtect = 0;
                if (m_hookStruct[i].AllocationProtect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) 
                {
                    if (NT_SUCCESS(ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, m_hookStruct[i].AllocationProtect, &oldProtect)))
                    {
                        memcpy(m_hookStruct[i].pTarget, m_hookStruct[i].hookCode, sizeof(m_hookStruct[i].hookCode));
                        m_hookStruct[i].bSucceedHook = TRUE;
                        ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, oldProtect, &oldProtect);
                        bRet = TRUE;
                    }
                }
            }
        }
        else 
        {
            if (m_hookStruct[i].pTarget == pTarget)
            {
               if (!m_hookStruct[i].bSucceedHook)
               {
                   if (m_hookStruct[i].AllocationProtect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                   {
                       SIZE_T nSize = 1;
                       PVOID nBaseAddress = m_hookStruct[i].pTarget;
                       DWORD oldProtect = 0;
                       if (NT_SUCCESS(ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, m_hookStruct[i].AllocationProtect, &oldProtect)))
                       {
                           memcpy(m_hookStruct[i].pTarget, m_hookStruct[i].hookCode, sizeof(m_hookStruct[i].hookCode));
                           m_hookStruct[i].bSucceedHook = TRUE;
                           ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, oldProtect, &oldProtect);
               
                       }
               
                   }
               }
               break;
            }
        }
    }

    LeaveSpinLock();

    return 0;
}

void __stdcall hook::DisableHook(PVOID pTarget)
{
    if (!m_Initialize)return;

    EnterSpinLock();
    for (int i = 0; i < m_CurrentHookSize; i++)
    {
        if (!pTarget) 
        {
            if (m_hookStruct[i].bSucceedHook)
            {
                if (m_hookStruct[i].AllocationProtect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                {
                    SIZE_T nSize = 1;
                    PVOID nBaseAddress = m_hookStruct[i].pTarget;
                    DWORD oldProtect = 0;
                    if (NT_SUCCESS(ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, m_hookStruct[i].AllocationProtect, &oldProtect)))
                    {
                        memcpy(m_hookStruct[i].pTarget, &m_hookStruct[i].orgCode[m_hookStruct[i].orgCodePos], m_hookStruct[i].nOrgLen);
                        m_hookStruct[i].bSucceedHook = FALSE;
                        ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, oldProtect, &oldProtect);

                    }

                }

            }
        }
        else 
        {
            if (m_hookStruct[i].pTarget == pTarget)
            {
               if (m_hookStruct[i].bSucceedHook)
               {
                   if (m_hookStruct[i].AllocationProtect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                   {
                       SIZE_T nSize = 1;
                       PVOID nBaseAddress = m_hookStruct[i].pTarget;
                       DWORD oldProtect = 0;
                       if (NT_SUCCESS(ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, m_hookStruct[i].AllocationProtect, &oldProtect)))
                       {
                           memcpy(m_hookStruct[i].pTarget, &m_hookStruct[i].orgCode[m_hookStruct[i].orgCodePos], m_hookStruct[i].nOrgLen);
                           m_hookStruct[i].bSucceedHook = FALSE;
                           ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, oldProtect, &oldProtect);
                       }
               
                   }
               }
               break;
            }
        }
    }
    LeaveSpinLock();

    return;
}

int hook::FindCall(PVOID code, int size)
{
	char* ptr = static_cast<char*>(const_cast<void*>(code));
	int i = 0, j = 0;
    BOOL bFind = FALSE;
	while (i < size)
	{
		hde64s hs;
		hde64_disasm(ptr + i, &hs);

        if (hs.opcode == 0xE8) 
        {
            bFind = FALSE;
            break;
        }
        if (hs.opcode == 0xE9) 
        {
            bFind = FALSE;
            break;
        }

        if (!hs.len) 
        {
            bFind = FALSE;
            break;
        }
		i += hs.len;
        bFind = TRUE;
	}
    if (bFind)
    {
        return  i;
    }

	return 0;
}

PVOID hook::FindE9(PVOID code, int num, int size)
{
    char* ptr = static_cast<char*>(const_cast<void*>(code));
	int i = 0, j = 0;
	while (i < size)
	{
		hde64s hs;
		hde64_disasm(ptr + i, &hs);
		if (hs.opcode != 0xE9 && ++j == num)
		{
			// 返回 call 后面的地址
			return ptr + i + hs.len + static_cast<int>(hs.imm.imm32);
		}
		if (!hs.len) break;
		i += hs.len;
	}
	return nullptr;
}

PVOID hook::Initialize()
{
    RtlSecureZeroMemory(&m_hookStruct, sizeof(m_hookStruct));
    InitSysCallIndex(&g_SysCallIndex);
    HANDLE hSection = 0;
	LARGE_INTEGER cbSectionOffset = {};
    PVOID pViewBase = NULL;
    SIZE_T cbViewSize = 0;
    NTSTATUS ntstatus = 0;
	LARGE_INTEGER cbSectionSize = { 0 };
	cbSectionSize.QuadPart = PAGE_SIZE;
	ntstatus = ZwCreateSection(
     &hSection,
     SECTION_ALL_ACCESS,
     NULL,
     &cbSectionSize,
     PAGE_EXECUTE_READWRITE,
     SEC_COMMIT,
     NULL);
    if (NT_SUCCESS(ntstatus))
    {
        pViewBase = (PVOID)0x01000000;

        do
        {
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
            if(NT_SUCCESS(ntstatus))
            {
                m_AllcoateMemoryNoChange = pViewBase;
                break;
            }
            pViewBase = (PVOID)((ULONG_PTR)pViewBase + PAGE_SIZE * 0x10);

        } while (!NT_SUCCESS(ntstatus) && ((ULONG_PTR)pViewBase < 0x7f000000));

        if (NT_SUCCESS(ntstatus))
        {
            
            pViewBase = NULL;
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
            if (NT_SUCCESS(ntstatus))
            {
                m_pAllcoateMemory = pViewBase;
                m_Initialize = TRUE;
            }
        }


    }
    if (hSection)
    {
       ntstatus = ZwClose(hSection);
    }


    return m_AllcoateMemoryNoChange;
}

VOID __stdcall hook::Uninitialize(VOID)
{
   if (!m_Initialize)return;


    EnterSpinLock();
    for (int i = 0; i < m_CurrentHookSize; i++)
    {
        if (m_hookStruct[i].bSucceedHook)
        {
            if (m_hookStruct[i].AllocationProtect & (PAGE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            {
                SIZE_T nSize = 1;
                PVOID nBaseAddress = m_hookStruct[i].pTarget;
                DWORD oldProtect = 0;
                if (NT_SUCCESS(ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, m_hookStruct[i].AllocationProtect, &oldProtect)))
                {
                    memcpy(m_hookStruct[i].pTarget, &m_hookStruct[i].orgCode[m_hookStruct[i].orgCodePos], m_hookStruct[i].nOrgLen);
                    m_hookStruct[i].bSucceedHook = FALSE;
                    ZwProtectVirtualMemory(NtCurrentProcess(), &nBaseAddress, &nSize, oldProtect, &oldProtect);

                }

            }

        }
    }
    m_Initialize = FALSE;
    
    if (m_pAllcoateMemory) {
        ZwUnmapViewOfSection(NtCurrentProcess(), m_pAllcoateMemory);
        m_pAllcoateMemory = NULL;
    }
    if (m_AllcoateMemoryNoChange) {
        ZwUnmapViewOfSection(NtCurrentProcess(), m_AllcoateMemoryNoChange);
        m_AllcoateMemoryNoChange = NULL;
    }

    LeaveSpinLock();

    return;
}

VOID hook::LeaveSpinLock(VOID)
{
    InterlockedExchange(&m_isLocked, FALSE);
}

VOID hook::EnterSpinLock(VOID)
{
    SIZE_T spinCount = 0;

    // Wait until the flag is FALSE.
    /*
    * InterlockedCompareExchange是把目标操作数（第1参数所指向的内存中的数）与一个值（第3参数）比较，
    如果相等，则用另一个值（第2参数）与目标操作数（第1参数所指向的内存中的数）交换；

    返回值:InterlockedCompareExchange 返回 参数一的原始值。
    */
    while (InterlockedCompareExchange(&m_isLocked, TRUE, FALSE) != FALSE)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spinCount < 32)
            sleep(0);
        else
            sleep(1);

        spinCount++;
    }
}

ULONG hook::sleep(ULONG n)
{
     LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 1000 * n; // =SleepEx(1000, TRUE);

    return ZwDelayExecution(FALSE, &timeout);
}
