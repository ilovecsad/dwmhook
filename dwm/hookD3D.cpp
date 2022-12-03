#include "hookD3D.h"
#include "CIMGuiDraw.h"
#include "searchSign.h"
#include "pch.h"
#include <intrin.h>
#include "ScreenGrab11.h"
#include <wincodec.h>
#include "WICTextureLoader11.h"
#include <wrl.h>

PDRWARR pDrawList = NULL;
HWND g_hwnd = NULL;
CIMGuiDraw g_ImGuiDraw;

PVOID orgGetBuffer = NULL;
EXTERN_C PVOID orgGetBufferAsm = NULL;

VOID WINAPI BreakOnAccessCallBack(
	PEXCEPTION_POINTERS pEp
	)
{
	g_ImGuiDraw.ImGuiDx11DrawTestDemo();
}


void test()
{
	g_exceptionhook->CreateHardWare(g_pSwapChain, BreakOnAccess, BreakOnAccessCallBack);
	g_exceptionhook->EnableHardWare();
}


VOID   DrawEverything( IDXGISwapChain* pDxgiSwapChain )
{
	
	static bool b = true;
	static bool bAlreadHook = false;
	if ( b )
	{
		InterlockedExchange((LONG*)&b, 0);

		ID3D11Device* pDevice = NULL;
		pDxgiSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pDevice);
		//初始化migui

		g_hwnd = FindWindow(L"Progman", L"Program Manager");
		if (g_hwnd) 
		{
			ck_printf("hzw:在此窗口绘制 hwnd:%x \n",g_hwnd);
			if (g_ImGuiDraw.InitMiGuiDx11Hook(pDxgiSwapChain, pDevice, g_hwnd))
			{
				if (g_ImGuiDraw.InitMessage())
				{
					pDrawList = g_ImGuiDraw.GetPointer();
					bAlreadHook = true;

	
					
	
					ck_printf("hzw:通讯初始化成功! pDxgiSwapChain[%p] \n",pDxgiSwapChain);

		
				}
			}
		}
		
	}
	else
	{
		if (bAlreadHook) 
		{
			//g_ImGuiDraw.ImGuiDx11Draw();
			//g_ImGuiDraw.ImGuiDx11DrawTestDemo();
			g_hook->DisableHook();
			//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)test, 0, 0, 0);
		}

	}

}


VOID   DrawEverythingEx( IDXGISwapChain* pDxgiSwapChain )
{
	
	static bool b = true;
	static bool bAlreadHook = false;
	if ( b )
	{
		InterlockedExchange((LONG*)&b, 0);

		ID3D11Device* pDevice = NULL;
		pDxgiSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pDevice);
		//初始化migui

		g_hwnd = FindWindow(L"Progman", L"Program Manager");
		if (g_hwnd) 
		{
			ck_printf("hzw:在此窗口绘制 hwnd:%x \n",g_hwnd);
			if (g_ImGuiDraw.InitMiGuiDx11Hook(pDxgiSwapChain, pDevice, g_hwnd))
			{
				if (g_ImGuiDraw.InitMessage())
				{
					pDrawList = g_ImGuiDraw.GetPointer();
					bAlreadHook = true;




					ck_printf("hzw:通讯初始化成功! pDxgiSwapChain[%p]\n",pDxgiSwapChain);

		
				}
			}
		}
		
	}
	else
	{
		if (bAlreadHook) 
		{
			g_ImGuiDraw.ImGuiDx11Draw();
			//g_ImGuiDraw.ImGuiDx11DrawTestDemo();
		}

	}

}




__int64 __fastcall DXGIPresentDWM(IDXGISwapChain* pDXGISwapChain, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6,
	__int64 a7, __int64 a8,__int64 a9,__int64 a10)
{
	//g_work->printfStackFrame("hzw:DXGIPresentDWM");

	//DrawEverything(pDXGISwapChain);
	DrawEverythingEx(pDXGISwapChain);

	return ((t_DXGIPresentMultiplaneOverlay)g_dxgi.jmpOrgPresentDWM)(pDXGISwapChain,a2,a3,a4,a5,a6,a7,a8,a9,a10);
}

HRESULT DXGIGetBuffer(IDXGISwapChain* pDxgiSwapChain, UINT Buffer, const _GUID* riid, void** ppSurface)
{
	__debugbreak();
	HRESULT h = S_FALSE;
	ID3D11Texture2D* pBackBuffer = NULL;
	h = ((t_DXGIGetBuffer)orgGetBuffer)(pDxgiSwapChain, Buffer, riid,  (void**)&pBackBuffer);
	if (h == S_OK)
	{
		h = pBackBuffer->Release();
		h = DirectX::CreateWICTextureFromFile(g_pd3dDevice, L"C:\\123456.png", (ID3D11Resource**)(ppSurface), NULL);
		ck_printf("hzw:HookGetBuffer->CreateWICTextureFromFile:%x %d %p \n", h, GetLastError(), ppSurface);
	}

	return h;
}

HRESULT DXGIGetBufferEx(void** ppSurface)
{
	HRESULT h = S_FALSE;
	if (*ppSurface) {
		ID3D11Texture2D* pBackBuffer = (ID3D11Texture2D*)*ppSurface;
		h = S_OK;
		pBackBuffer->Release();
		h = DirectX::CreateWICTextureFromFile(g_pd3dDevice, L"C:\\123456.png", (ID3D11Resource**)(ppSurface), NULL);
		ck_printf("hzw:HookGetBuffer->CreateWICTextureFromFile:%x %d %p \n", h, GetLastError(), ppSurface);
	}
	return h;
}






__int64 __fastcall D2D1PresentMultiplaneOverlay_HookCall(void* thisptr, IDXGISwapChain* pDxgiSwapChain, unsigned __int64 a3, unsigned __int64 a4, __int64 a5, __int64 a6, __int64 a7, __int64 a8, __int64 a9, __int64 a10)
{
	//DrawEverything(pDxgiSwapChain);
	DrawEverythingEx(pDxgiSwapChain);
	return ((t_D2D1PresentMultiplaneOverlay)g_d2d1.jmppCallPresentMultiplaneOverlay)(thisptr,pDxgiSwapChain,a3,a4,a5,a6,a7,a8,a9,a10);
}


void draw()
{
	g_ImGuiDraw.ImGuiDx11DrawTestDemo();
	return ;
}

void draw2(IDXGISwapChain* pDxgiSwapChain)
{
	DrawEverything(pDxgiSwapChain);
}








