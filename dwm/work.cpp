#include "work.h"
#include "hookD3D.h"


dxgi_fun g_dxgi;
d2d1_fun g_d2d1;


EXTERN_C DWORD64 jmpOrgPresentDWM2 = 0;
EXTERN_C DWORD64 jmpOrgPresentDWM3 = 0;

// 经过实验验证 vm虚拟机 只有 dxgi.dll->PresentDWM 这条路
// 物理机 dxgi.dll->PresentMultiplaneOverlay 和 d2d1->PresentMultiplaneOverlay 都可以走通
BOOL work::initPtr()
{

	BOOL bRet = FALSE;
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

	//48 89 41 10 48 8D 05 ?? ?? ?? ??   ->finnd PresentDWM PresentMultiplaneOverlay
	auto dwRender = FindPattern("dxgi.dll", PBYTE("\x48\x89\x41\x10\x48\x8D\x05\x00\x00\x00\x00"), "xxxxxxx????");
	//48 8B D9 48 8D 05 ?? ?? ?? ?? 48 89 01"  ->find GetBuffer  Present

	//mov     [rdi+50h], rsi lea     rax, ??_7CDXGISwapChain@@6BIDXGISwapChain4@@@  48 89 77 50 48 8D 05 ?? ?? ?? ??



	auto dwRender2 = FindPattern("dxgi.dll", PBYTE("\x48\x8B\xD9\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x01"), "xxxxxx????xxx");


	//8A 44 24 60 8A 01 88 84 24 90 00 00 00 8A 84 24 90 00 00 00 8B 84 24 98 00 00 00 89 44 24 38 48 8B 84 24 88 00 00 00 48 89 4C 24 30
	auto pCallPresentMultiplaneOverlay = FindPattern("d2d1.dll", 
		PBYTE("\x8A\x44\x24\x60\x8A\x01\x88\x84\x24\x90\x00\x00\x00\x8A\x84\x24\x90\x00\x00\x00\x8B\x84\x24\x98\x00\x00\x00\x89\x44\x24\x38\x48\x8B\x84\x24\x88\x00\x00\x00\x48\x89\x4C\x24\x30"), 
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");


	if (dwRender && dwRender2 &&  pCallPresentMultiplaneOverlay )
	{

		__try 
		{
			dwRender = ResolveRelative(dwRender + 4);
			dwRender2 = ResolveRelative(dwRender2 + 3);

			PDWORD_PTR Vtbl = PDWORD_PTR(dwRender);
			PDWORD_PTR Vtbl2 = PDWORD_PTR(dwRender2);
	
			g_dxgi.orgPresentDWM = Vtbl[16];

		
			g_d2d1.pCallPresentMultiplaneOverlay = pCallPresentMultiplaneOverlay + 0x3f;

		}
		__except (1)
		{

		}
		if (g_dxgi.orgPresentDWM  && g_d2d1.pCallPresentMultiplaneOverlay) 
		{
			bRet = TRUE;
		}
	}
	ck_printf("hzw:dxgi:PresentDWM[%p]PresentMultiplaneOverlay[%p]\n", g_dxgi.orgPresentDWM, g_d2d1.pCallPresentMultiplaneOverlay);

	return bRet;
}


BOOL work::HookVmmvareMachine()
{

	g_hook->CreateHook((PVOID)g_dxgi.orgPresentDWM, DXGIPresentDWM, (PVOID*)&g_dxgi.jmpOrgPresentDWM);

	//g_dxgi.orgPresentDWM2 = (DWORD64)g_hook->FindCall((PVOID)g_dxgi.orgPresentDWM) + g_dxgi.orgPresentDWM;
	//g_hook->CreateHook((PVOID)g_dxgi.orgPresentDWM2, ImGuiDraw, (PVOID*)&g_dxgi.jmpOrgPresentDWM2);
	//jmpOrgPresentDWM2 = g_dxgi.jmpOrgPresentDWM2;
	g_hook->EnableHook();


	return 1;
}

BOOL work::HookVmmvareMachine2()
{
	//dxgi.dll+5CFB - 4C 89 54 24 38        - mov [rsp+38],r10 版本->22h2
	g_dxgi.orgPresentDWM = (DWORD64)GetModuleHandle(L"dxgi.dll") + 0x5CFB;
	g_hook->CreateHook((PVOID)g_dxgi.orgPresentDWM, ImGuiDraw2, (PVOID*)&jmpOrgPresentDWM3);
	g_hook->EnableHook();
	return 0;
}





BOOL work::HookPhysicalMachine()
{
	g_hook->CreateCallHook((PVOID)g_d2d1.pCallPresentMultiplaneOverlay, D2D1PresentMultiplaneOverlay_HookCall,(PVOID*)&g_d2d1.jmppCallPresentMultiplaneOverlay);
	g_hook->EnableHook();
	
	return 1;
}

void work::printfStackFrame(char* szSign)
{
	char psz[MAX_PATH] = { 0 };
	PVOID* pTemp = (PVOID*)psz;

	WORD c=  RtlCaptureStackBackTrace(0, sizeof(psz) / 8, pTemp, NULL);

	for (int i = 0; i < c; i++)
	{
		ck_printf("%s->[%p]", szSign,pTemp[i]);
	}
}