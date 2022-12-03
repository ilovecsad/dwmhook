#pragma once
#include <Windows.h>

#include "ImGui\imgui.h"
#include "ImGui\imgui_internal.h"
#include "ImGui\imgui_impl_dx11.h"
#include "IMGUI/MyImGui.h"

VOID  DrawEverything(IDXGISwapChain* pDxgiSwapChain);
VOID   DrawEverythingEx(IDXGISwapChain* pDxgiSwapChain);

//’‚¿Ô «dxgi
typedef HRESULT (__fastcall *t_DXGIGetBuffer)(IDXGISwapChain* pDxgiSwapChain,UINT   Buffer,const struct _GUID * riid,void** ppSurface);
typedef __int64 (__fastcall *t_DXGIPresentMultiplaneOverlay)(IDXGISwapChain *pDXGISwapChain, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6,
                                   __int64 a7, __int64 a8,__int64 a9,__int64 a10);

typedef __int64 (__fastcall *t_DXGIResizeBuffers)(IDXGISwapChain* pDXGISwapChain, unsigned int a2, unsigned int a3, unsigned int a4);

EXTERN_C __int64 __fastcall DXGIPresentDWM(IDXGISwapChain* pDXGISwapChain, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6,
	__int64 a7, __int64 a8,__int64 a9,__int64 a10);

HRESULT DXGIGetBuffer(IDXGISwapChain* pDxgiSwapChain, UINT   Buffer, const struct _GUID * riid, void** ppSurface);
EXTERN_C HRESULT DXGIGetBufferAsm();
EXTERN_C HRESULT DXGIGetBufferEx(void** ppSurface);
// d2d1
//typedef __int64 (__fastcall *t_D2D1PresentDWM)(void* thisptr, IDXGISwapChain* pDxgiSwapChain, unsigned int a3, unsigned int a4, const struct tagRECT* a5, unsigned int a6, const struct DXGI_SCROLL_RECT* a7, unsigned int a8, struct IDXGIResource* a9, unsigned int a10);
typedef __int64 (__fastcall *t_D2D1PresentMultiplaneOverlay)(void* thisptr, IDXGISwapChain* pDxgiSwapChain, unsigned __int64 a3, unsigned __int64 a4, __int64 a5, __int64 a6, __int64 a7, __int64 a8,__int64 a9,__int64 a10);



__int64 __fastcall D2D1PresentMultiplaneOverlay_HookCall(void* thisptr, IDXGISwapChain* pDxgiSwapChain, unsigned __int64 a3, unsigned __int64 a4, __int64 a5, __int64 a6, __int64 a7, __int64 a8,__int64 a9,__int64 a10);

EXTERN_C void draw();
EXTERN_C void  ImGuiDraw();


EXTERN_C void draw2(IDXGISwapChain* pDxgiSwapChain);
EXTERN_C void  ImGuiDraw2();
