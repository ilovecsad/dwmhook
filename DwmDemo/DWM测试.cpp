// DWM测试.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "dwmIo.h"
ImVec4 white = { 255, 255, 255, 255 };
ImVec4 green = { 0, 255, 0, 255 };
ImVec4 red = { 255, 0, 0, 255 }; //RGBA
int main()
{
	
	PDRWARR info = NULL;
	HWND hwnd = ::FindWindowW(NULL,L"Calculator");
	BOOL b = FALSE;

	if (hwnd)
	{
		if (InitDwm())
		{
			while (1)
			{
				if (DwmStartDraw(hwnd))
				{

					for (int i = 0; i < 90; i++) 
					{
						draw_text(1 + i, 1 + i, &green, "sadasdas");
						draw_line(10 + i, 10 + i, 20 + i, 20 + i, &red, 1);
						draw_rect(30 + i, 30 + i, 50 + i, 50 + i, &red, 1);
						DrawCircle(50 + i, 50 + i, 10 + i, &red, 10, 1);
						DrawCircleFilled(40 + i, 40 + i, 10,&red, 10);
						
					}
					DwmEndDraw();
					info = GetPointer();
					if (!b)
					{
						b = 1;
						info->m_keyState[VK_PAUSE] = 1;
					}
					SetTargetWindowsPos(hwnd);
					
				}
				//Sleep(1);
			}
		}
	}
	return 0;
}



//#include "payload.hpp"
//
//ImVec4 white = { 255, 255, 255, 255 };
//ImVec4 green = { 0, 255, 0, 255 };
//ImVec4 red = { 255, 0, 0, 255 }; //RGBA
//DWORD __stdcall ZwMapViewOfSection_(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
//{
//	DWORD n = 0;
//    pdwm_pointer pDwm = (pdwm_pointer)DWM_DATA_BASE;
//	pDwm->nNtFunIndex =0x28;
//	t_ZwMapViewOfSection ZwMapViewOfSection = (t_ZwMapViewOfSection)pDwm->pfnSysCall;
//	n = ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
//	pDwm->nNtFunIndex = 0;
//	return n;
//}
//
//int main()
//{
//
//	PVOID pAllcoate = VirtualAlloc(NULL, sizeof(DWM::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	if (pAllcoate) 
//	{
//		RtlCopyMemory(pAllcoate, DWM::payload, sizeof(DWM::payload));
//		DWORD oldProtect = NULL;
//		if (!VirtualProtect(pAllcoate, 0x1000, PAGE_EXECUTE_READ, &oldProtect)) { return 0; }
//
//		pdwm_pointer pDwm = (pdwm_pointer)DWM_DATA_BASE;
//		ULONG_PTR nAllcoatePos = (ULONG_PTR)pAllcoate;
//		
//		pDwm->pfnSysCall    = (t_SysCall)(nAllcoatePos + 0x89f);
//		pDwm->pfnInitDwm    = (t_InitDwm)(nAllcoatePos + DWM::rva::InitDwm);
//		pDwm->pfnDwmStartDraw = (t_DwmStartDraw)(nAllcoatePos + DWM::rva::DwmStartDraw);
//		pDwm->pfnDwmEndDraw = (t_DwmEndDraw)(nAllcoatePos + DWM::rva::DwmEndDraw);
//		pDwm->pfnSetTargetWindowsPos = (t_SetTargetWindowsPos)(nAllcoatePos + DWM::rva::SetTargetWindowsPos);
//		pDwm->pfnDraw_text = (t_draw_text)(nAllcoatePos + DWM::rva::draw_text);
//		pDwm->pfnDrawCircle = (t_DrawCircle)(nAllcoatePos + DWM::rva::DrawCircle);
//		pDwm->pfnDrawCircleFilled = (t_DrawCircleFilled)(nAllcoatePos + DWM::rva::DrawCircleFilled);
//		pDwm->pfnDraw_rect = (t_draw_rect)(nAllcoatePos + DWM::rva::draw_rect);
//		pDwm->pfnDrawFilledRect = (t_DrawFilledRect)(nAllcoatePos + DWM::rva::DrawFilledRect);
//		pDwm->pfnDraw_line = (t_draw_line)(nAllcoatePos + DWM::rva::draw_line);
//		pDwm->pfnIsPointInWindowsRect = (t_IsPointInWindowsRect)(nAllcoatePos + DWM::rva::IsPointInWindowsRect);
//		pDwm->pfnMemcpy_ = (t_memcpy_)(nAllcoatePos + DWM::rva::memcpy_);
//		pDwm->pfnGetPointer = (t_GetPointer)(nAllcoatePos + DWM::rva::GetPointer);
//
//		PDRWARR info = NULL;
//		HWND hwnd = ::FindWindowW(L"WTWindow", L"计算器");
//		if (hwnd)
//		{
//	
//			PVOID pMap = NULL;
//			HANDLE hMap= CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, NULL);
//			SIZE_T nViewSize = 0;
//		    LARGE_INTEGER cbSectionOffset;
//		    cbSectionOffset.QuadPart = 0;
//		    
//		    PVOID dwTemp = NULL;
//		    ZwMapViewOfSection_(hMap, NtCurrentProcess(), &dwTemp, 0, 0, &cbSectionOffset, &nViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
//
//			printf("%p\n",pAllcoate);
//			
//			if (pDwm->pfnInitDwm())
//			{
//				while (1)
//				{
//					if (1/*VirtualProtect(pAllcoate, 0x1000, PAGE_EXECUTE_READ, &oldProtect)*/)
//					{
//						if (pDwm->pfnDwmStartDraw(hwnd))
//						{
//
//							for (int i = 0; i < 100; i++)
//							{
//								pDwm->pfnDraw_text(1 + i, 1 + i, &green, "sadasdas");
//								pDwm->pfnDraw_line(10 + i, 10 + i, 20 + i, 20 + i, &red, 1);
//								pDwm->pfnDraw_rect(30 + i, 30 + i, 50 + i, 50 + i, &red, 1);
//								pDwm->pfnDrawCircle(50 + i, 50 + i, 10 + i, &red, 10, 1);
//								pDwm->pfnDrawCircleFilled(40 + i, 40 + i, 10, &red, 10);
//
//							}
//							pDwm->pfnDrawFilledRect(100 , 100 , 200, 200, &red, 1);
//							info = pDwm->pfnGetPointer();
//							pDwm->pfnDwmEndDraw();
//							pDwm->pfnSetTargetWindowsPos(hwnd);
//
//						}
//						//VirtualProtect(pAllcoate, 0x1000, PAGE_NOACCESS, &oldProtect);
//					}
//					Sleep(1);
//				}
//			}
//		}
//		return 0;
//	}
//}