#pragma once
#include "importfun.h"

#define SAVE_CODE 50

typedef struct _HOOK_ENTRY_EX
{
    LPVOID pTarget;         
    LPVOID pDetour;         
    LPVOID pOriginal;  
    DWORD  nOrgLen;     //记录原始硬编码得长度
    DWORD  AllocationProtect;
	DWORD  orgCodePos;
    UINT8  bSucceedHook;
    UINT8  orgCode[SAVE_CODE];       
    UINT8  hookCode[6];  //push xxx ret   

} HOOK_ENTRY_EX, *PHOOK_ENTRY_EX;



class hook
{
public:
	hook();
	~hook();
	BOOL __stdcall CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal = NULL);
	BOOL __stdcall CreateCallHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal = NULL);//专门用来hook call xxxx
	BOOL WINAPI EnableHook(PVOID pTarget = NULL);
    void WINAPI DisableHook(PVOID pTarget = NULL);
    int FindCall(PVOID code,int size = 70);//参数1:起始地址 参数二:需要第几个Call 
    PVOID FindE9(PVOID code, int num = 1, int size = 70);//参数1:起始地址 参数二:需要第几个Call 
private:
	PVOID Initialize();
	VOID WINAPI Uninitialize(VOID);
	VOID LeaveSpinLock(VOID);
	VOID EnterSpinLock(VOID);
	ULONG sleep(ULONG n);
private:
	BOOL m_Initialize = FALSE;
	DWORD m_MaxHookSize = 0x50;
	DWORD m_CurrentHookSize = 0;
	LONG m_isLocked = FALSE;
	PVOID m_pAllcoateMemory = NULL;
	PVOID m_AllcoateMemoryNoChange = NULL;
	HOOK_ENTRY_EX m_hookStruct[0x50];
};

/*
https://www.cnblogs.com/kuangke/p/5480987.html
注:不要HOOK 函数里可能会被跳转的地址, 不要HOOK 字节中包含函数调用的地址 如 HOOK的地址里有 CALL EDX 等

x86

JMP计算公式
   目标地址-当前地址-5 = 机器码E9后面所跟的32位数
JE计算公式
   目标地址-当前地址-6 = 机器码0F 84后面所跟的32位数
JNE计算公式
   目标地址-当前地址-6 = 机器码0F 85后面所跟的32位数
CALL计算公式
   目标地址-下条指令的地址=机器码E8后面所跟的32位数  ret十六进制码 C3
x64

      jmp计算公式

             1 第一种方法 jmp qword ptr[ 保存目标地址的指针地址]

             保存目标地址的指针地址-下条指令的地址= 特征码 FF 25 后面跟着的32位数  

                 （注意保存目标地址的指针地址 和 下条指令地址 都必须在一个PE段（section）） 而且  保存目标地址的指针地址 必须在 下条指令的地址下面

                  计算下条指令方法就是 FF 25 32位数 总共 六个字节

                  保存目标地址的指针地址 必须是 八个字节

                  总共 14 个字节

             2  第二种方法

               push r15

                    mov r15, 目标地址

                    jmp r15    

                   到目标地址一系列操作后 还原 r15 pop               

               pop r15 

            3 第三种方法

                mov r15，目标地址

                push r15

                ret

 

             个人建议 使用 第一种方法

     CALL地址计算 当前地址4字节 + E8 后面的4字节 + 5
*/