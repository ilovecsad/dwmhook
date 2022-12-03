#pragma once
#include <Windows.h>
#include <list>

#define _CRT_SECURE_NO_WARNINGS

/*
R/W0 - R/W3 读写域 四个读写域分别与DR0-DR3寄存器所对应，用来指定被监控地点的访问类型。

占两位，所以有以下四种状态：

00：仅执行对应断点的时候中断（执行断点）

01：仅写数据中断（写入断点）

10：（需要开启CR4的DE【调试扩展】）I/O时中断

11：读写数据都中断，但是读指令除外（访问断点）

LEN0 - LEN3 长度域 四个长度域分别与DR0-DR3寄存器所对应，用来指定监控区域的长度

占两位，所以有以下四种状态：

00：1字节长

01：2字节长

10：8字节长

11：4字节长
————————————————
版权声明：本文为CSDN博主「极安御信安全研究院」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/m0_64973256/article/details/122239792
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
		unsigned BS : 1;       //单步异常 BS位会被置1
		unsigned Reverted2 : 17;
	}fields;
};






// 在异常回调函数里跑你得代码,不需要考虑寄存器恢复的问题
/*
* 1.但要 注意一个问题 假设你对 MessageboxW 下了个硬件断点，这个时候你就不要在你的回调里执行 MessageboxW
* 否则 该线程将陷于 一个死循环，知道堆栈溢出而崩溃
* 
* 2.你可以在回调函数里 更改RIP 当更改RIP 可能会出现 寄存器原始值损失问题
* 
* 3.最好 不要再调用函数中触发异常，可能会崩
*/
typedef VOID (WINAPI *ExceptionCallBack)(
    PEXCEPTION_POINTERS pEp
    );

enum BreakType
{
	BreakOnExecute = 0,//仅执行对应断点的时候中断（执行断点）
	BreakOnWrite =1,//仅写数据中断（写入断点） 
	BreakOnAccess=3 //读写数据都中断，但是读指令除外（访问断点）
};

enum BreakLength
{
	BreakOnByte = 0,//00：1字节长
	BreakOnShort = 1,//00：2字节长
	BreakOnDWORD64 = 2,//00：8字节长
	BreakOnDWORD = 3 //00：4字节长
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
	LPVOID pDefaultFunc; //跳板地址 
	ExceptionCallBack pCallBack;
    DWORD  AllocationProtect;//记录原始的内存属性
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

	//极度消耗 效率  最好只设置一个
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
	PVOID m_pAllcoateMemory = NULL; //记录跳板内存
	int m_MaxHookSize = 0x50;     //记录最大的钩子 
	LONG m_CurrentHookSize = 0;   //记录当前的钩子数量

	int m_nHardWareCurrentCnt = 0;       //记录当前硬件断点类型的数量
	int m_nHardWareMaxCnt = 4;          //记录硬件断点类型的最大钩子数量
	BOOL m_bSetAceessViolation = FALSE;
	PVOID m_VehHandler = NULL;
	BOOL m_Initialize = FALSE;
	HardWareData m_hardWareArry;
	std::list<BreakPointData> m_BreakPointList;
	std::list<AceessViolationData> m_AceessViolationList;
};

extern exceptionhook* g_exceptionhook;


typedef ULONG(NTAPI* t_ZwContinue_)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
