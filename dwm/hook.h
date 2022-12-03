#pragma once
#include "importfun.h"

#define SAVE_CODE 50

typedef struct _HOOK_ENTRY_EX
{
    LPVOID pTarget;         
    LPVOID pDetour;         
    LPVOID pOriginal;  
    DWORD  nOrgLen;     //��¼ԭʼӲ����ó���
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
	BOOL __stdcall CreateCallHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal = NULL);//ר������hook call xxxx
	BOOL WINAPI EnableHook(PVOID pTarget = NULL);
    void WINAPI DisableHook(PVOID pTarget = NULL);
    int FindCall(PVOID code,int size = 70);//����1:��ʼ��ַ ������:��Ҫ�ڼ���Call 
    PVOID FindE9(PVOID code, int num = 1, int size = 70);//����1:��ʼ��ַ ������:��Ҫ�ڼ���Call 
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
ע:��ҪHOOK ��������ܻᱻ��ת�ĵ�ַ, ��ҪHOOK �ֽ��а����������õĵ�ַ �� HOOK�ĵ�ַ���� CALL EDX ��

x86

JMP���㹫ʽ
   Ŀ���ַ-��ǰ��ַ-5 = ������E9����������32λ��
JE���㹫ʽ
   Ŀ���ַ-��ǰ��ַ-6 = ������0F 84����������32λ��
JNE���㹫ʽ
   Ŀ���ַ-��ǰ��ַ-6 = ������0F 85����������32λ��
CALL���㹫ʽ
   Ŀ���ַ-����ָ��ĵ�ַ=������E8����������32λ��  retʮ�������� C3
x64

      jmp���㹫ʽ

             1 ��һ�ַ��� jmp qword ptr[ ����Ŀ���ַ��ָ���ַ]

             ����Ŀ���ַ��ָ���ַ-����ָ��ĵ�ַ= ������ FF 25 ������ŵ�32λ��  

                 ��ע�Ᵽ��Ŀ���ַ��ָ���ַ �� ����ָ���ַ ��������һ��PE�Σ�section���� ����  ����Ŀ���ַ��ָ���ַ ������ ����ָ��ĵ�ַ����

                  ��������ָ������� FF 25 32λ�� �ܹ� �����ֽ�

                  ����Ŀ���ַ��ָ���ַ ������ �˸��ֽ�

                  �ܹ� 14 ���ֽ�

             2  �ڶ��ַ���

               push r15

                    mov r15, Ŀ���ַ

                    jmp r15    

                   ��Ŀ���ַһϵ�в����� ��ԭ r15 pop               

               pop r15 

            3 �����ַ���

                mov r15��Ŀ���ַ

                push r15

                ret

 

             ���˽��� ʹ�� ��һ�ַ���

     CALL��ַ���� ��ǰ��ַ4�ֽ� + E8 �����4�ֽ� + 5
*/