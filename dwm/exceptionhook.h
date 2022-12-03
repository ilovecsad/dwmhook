#pragma once
#include <Windows.h>
#include <list>

#define _CRT_SECURE_NO_WARNINGS

/*
R/W0 - R/W3 ��д�� �ĸ���д��ֱ���DR0-DR3�Ĵ�������Ӧ������ָ������صص�ķ������͡�

ռ��λ����������������״̬��

00����ִ�ж�Ӧ�ϵ��ʱ���жϣ�ִ�жϵ㣩

01����д�����жϣ�д��ϵ㣩

10������Ҫ����CR4��DE��������չ����I/Oʱ�ж�

11����д���ݶ��жϣ����Ƕ�ָ����⣨���ʶϵ㣩

LEN0 - LEN3 ������ �ĸ�������ֱ���DR0-DR3�Ĵ�������Ӧ������ָ���������ĳ���

ռ��λ����������������״̬��

00��1�ֽڳ�

01��2�ֽڳ�

10��8�ֽڳ�

11��4�ֽڳ�
��������������������������������
��Ȩ����������ΪCSDN�������������Ű�ȫ�о�Ժ����ԭ�����£���ѭCC 4.0 BY-SA��ȨЭ�飬ת���븽��ԭ�ĳ������Ӽ���������
ԭ�����ӣ�https://blog.csdn.net/m0_64973256/article/details/122239792
*/
union eflags
{
	ULONG64 all;
	struct 
	{
		unsigned CF : 1; 
		unsigned default1 : 1; 
		unsigned PF : 1; 
		unsigned default2 : 1; 
		unsigned AF : 1; 
		unsigned default3 : 1; 
		unsigned ZF : 1; 
		unsigned SF : 1; 
		unsigned TF : 1; 
		unsigned IF : 1; 
		unsigned DF : 1;
		unsigned OF : 1;
		unsigned IOPL : 2;
		unsigned NF : 1;
		unsigned default4 : 1;
		unsigned RF : 1;
		unsigned VM : 1;
		unsigned AC : 1;
		unsigned VIF : 1;
		unsigned VIP : 1;
		unsigned ID : 1;
	}fields;
};
union DR7 
{
	ULONG64 all;
	struct {
		unsigned l0 : 1;         //!< [0] Local Breakpoint Enable 0
		unsigned g0 : 1;         //!< [1] Global Breakpoint Enable 0
		unsigned l1 : 1;         //!< [2] Local Breakpoint Enable 1
		unsigned g1 : 1;         //!< [3] Global Breakpoint Enable 1
		unsigned l2 : 1;         //!< [4] Local Breakpoint Enable 2
		unsigned g2 : 1;         //!< [5] Global Breakpoint Enable 2
		unsigned l3 : 1;         //!< [6] Local Breakpoint Enable 3
		unsigned g3 : 1;         //!< [7] Global Breakpoint Enable 3
		unsigned le : 1;         //!< [8] Local Exact Breakpoint Enable
		unsigned ge : 1;         //!< [9] Global Exact Breakpoint Enable
		unsigned reserved1 : 1;  //!< [10] Always 1
		unsigned rtm : 1;        //!< [11] Restricted Transactional Memory
		unsigned reserved2 : 1;  //!< [12] Always 0
		unsigned gd : 1;         //!< [13] General Detect Enable
		unsigned reserved3 : 2;  //!< [14:15] Always 0
		unsigned rw0 : 2;        //!< [16:17] Read / Write 0
		unsigned len0 : 2;       //!< [18:19] Length 0
		unsigned rw1 : 2;        //!< [20:21] Read / Write 1
		unsigned len1 : 2;       //!< [22:23] Length 1
		unsigned rw2 : 2;        //!< [24:25] Read / Write 2
		unsigned len2 : 2;       //!< [26:27] Length 2
		unsigned rw3 : 2;        //!< [28:29] Read / Write 3
		unsigned len3 : 2;       //!< [30:31] Length 3
	} fields;
};
union DR6
{
	ULONG64 all;
	struct {
		unsigned B0 : 1;
		unsigned B1 : 1;
		unsigned B2 : 1;
		unsigned B3 : 1;
		unsigned Reverted : 9;
		unsigned BD : 1;
		unsigned BS : 1;       //�����쳣 BSλ�ᱻ��1
		unsigned Reverted2 : 17;
	}fields;
};






// ���쳣�ص�����������ô���,����Ҫ���ǼĴ����ָ�������
/*
* 1.��Ҫ ע��һ������ ������� MessageboxW ���˸�Ӳ���ϵ㣬���ʱ����Ͳ�Ҫ����Ļص���ִ�� MessageboxW
* ���� ���߳̽����� һ����ѭ����֪����ջ���������
* 
* 2.������ڻص������� ����RIP ������RIP ���ܻ���� �Ĵ���ԭʼֵ��ʧ����
* 
* 3.��� ��Ҫ�ٵ��ú����д����쳣�����ܻ��
*/
typedef VOID (WINAPI *ExceptionCallBack)(
    PEXCEPTION_POINTERS pEp
    );

enum BreakType
{
	BreakOnExecute = 0,//��ִ�ж�Ӧ�ϵ��ʱ���жϣ�ִ�жϵ㣩
	BreakOnWrite =1,//��д�����жϣ�д��ϵ㣩 
	BreakOnAccess=3 //��д���ݶ��жϣ����Ƕ�ָ����⣨���ʶϵ㣩
};

enum BreakLength
{
	BreakOnByte = 0,//00��1�ֽڳ�
	BreakOnShort = 1,//00��2�ֽڳ�
	BreakOnDWORD64 = 2,//00��8�ֽڳ�
	BreakOnDWORD = 3 //00��4�ֽڳ�
};

struct SingleData{

	LPVOID pTarget;
	ExceptionCallBack pCallBack;
	BreakType nType;
	BreakLength nLength;
};

struct HardWareData{

	ULONG_PTR nDr0;
	ULONG_PTR nDr1;
	ULONG_PTR nDr2;
	ULONG_PTR nDr3;
	DR7 nDr7;
	SingleData nData[4];
};


struct BreakPointData
{
    LPVOID pTarget;   
	LPVOID pDefaultFunc; //�����ַ 
	ExceptionCallBack pCallBack;
    DWORD  AllocationProtect;//��¼ԭʼ���ڴ�����
    UINT8  orgCode[10];       
	BOOL bEnable;
	BOOL bDefault;
};



struct AceessViolationData
{
    LPVOID pTarget;         
    LPVOID pTargetBase;         
    LPVOID pTargetEnd;  

	ExceptionCallBack pCallBack;
    DWORD  AllocationProtect; 
	DWORD  SetNewProtect; 
	DWORD nOrgProtect;
	BOOL bEnable;
};



struct CriticalSectionLock
{
	CRITICAL_SECTION cs;

	void Init()
	{
		InitializeCriticalSection(&cs);
	}

	void Enter()
	{
		EnterCriticalSection(&cs);
	}

	void Leave()
	{
		LeaveCriticalSection(&cs);
	}
	void UnInit()
	{
		DeleteCriticalSection(&cs);
	}
};


class exceptionhook
{
public:
	exceptionhook(BOOL bHook = FALSE);
	~exceptionhook();

	BOOL WINAPI CreateHardWare(LPVOID pTarget, BreakType nType, ExceptionCallBack pCallBack, BreakLength nLength = BreakOnByte);
	BOOL EnableHardWare();
	VOID DisableHardWare(int DRn = -1);

	BOOL WINAPI CreateBreakPointException(LPVOID pTarget, ExceptionCallBack pCallBack, BOOL bDefault = TRUE);
	BOOL EnableBreakPointHook(LPVOID pTarget = NULL);
	VOID DisableBreakPointHook(LPVOID pTarget = NULL);

	//�������� Ч��  ���ֻ����һ��
	BOOL WINAPI CreateAceessViolationException(LPVOID pTarget, ExceptionCallBack pCallBack = NULL);
	BOOL EnableAceessViolationHook(LPVOID pTarget = NULL);
	VOID DisableAceessViolationHook(LPVOID pTarget = NULL);

	BOOL CreateJmpSpringBoard(LPVOID pTarget, LPVOID pDetour,LPVOID* ppRip ,LPVOID* ppOriginal = NULL, int nOffset = 0);
	BOOL CreateCallSpringBoard(LPVOID pTarget, LPVOID pDetour, LPVOID* ppRip, LPVOID* ppOriginal = NULL, int nOffset = 0);


private:
	static LONG __stdcall VehHandler(EXCEPTION_POINTERS* pExceptionInfo);
	static BOOL GetHardWareExceptionStruct(EXCEPTION_POINTERS* pExceptionInfo,SingleData* pes);
	static BOOL GetBreakPointData(PVOID nExceptionAddress, BreakPointData* pData);
	static BOOL GetAceessViolationData(PVOID nExceptionAddress,AceessViolationData* pData);

	BOOL SetDr7AndThreadContext(DR7* pDr7, CONTEXT* pct);
	BOOL CreateInt3(LPVOID pTarget,DWORD AllocationProtect);

	PVOID CreateOriginalShellcode(PVOID pTarget);
	void* SetWow64PrepareForException(void* ptr);
	static void Wow64PrepareForExceptionHook(PEXCEPTION_RECORD er, PCONTEXT ctx);
private:
	BOOL m_bHookKiDispatchException = FALSE;
	PVOID m_pAllcoateMemory = NULL; //��¼�����ڴ�
	int m_MaxHookSize = 0x50;     //��¼���Ĺ��� 
	LONG m_CurrentHookSize = 0;   //��¼��ǰ�Ĺ�������

	int m_nHardWareCurrentCnt = 0;       //��¼��ǰӲ���ϵ����͵�����
	int m_nHardWareMaxCnt = 4;          //��¼Ӳ���ϵ����͵����������
	BOOL m_bSetAceessViolation = FALSE;
	PVOID m_VehHandler = NULL;
	BOOL m_Initialize = FALSE;
	HardWareData m_hardWareArry;
	std::list<BreakPointData> m_BreakPointList;
	std::list<AceessViolationData> m_AceessViolationList;
};

extern exceptionhook* g_exceptionhook;


typedef ULONG(NTAPI* t_ZwContinue_)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
