#include "dwmIo.h"
#include <intrin.h>
#include <string>
#include <algorithm>

#pragma data_seg("ldata")
char shellSysCall64[] = { 0x48 ,0x31 ,0xC0 ,//xor rax,rax;
0x65 ,0x48 ,0xA1 ,0x60 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,//mov rax,gs:[60h];
0x8B ,0x80 ,0x00 ,0x0C ,0x00 ,0x00 ,//mov eax,[rax+00c00h];
0x85,0xC0 ,//test eax,eax
0x74 ,0x06 ,//je __exit;
0x4C ,0x8B ,0xD1 ,//mov r10,rcx;
0x0F ,0x05 ,//syscall;
0xC3 ,//ret;
0xB8 ,0x05 ,0x00 ,0x00 ,0xC0 ,//mov eax,00c0000005h;
0xC3 };//ret;
#pragma data_seg();
#pragma comment(linker,"/SECTION:ldata,RE")


PVOID SysCall()
{
	return (PVOID)&shellSysCall64;
}

BOOL InitDwm()
{

    BOOL bRet = FALSE;
   
	pdwm_pointer pDwm = (pdwm_pointer)DWM_DATA_BASE;
	PDRWARR pDrawList = pDwm->pDrawList;
 
    if (!pDrawList) 
    {
		
		HANDLE  m_hFileMapping = 0;
        m_hFileMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, MAPNAME);
		DWORD error = GetLastError();
        if (m_hFileMapping == NULL)
        {
            return bRet;
        }
		SIZE_T nViewSize = 0;
		LARGE_INTEGER cbSectionOffset;
		cbSectionOffset.QuadPart = 0;
		
		PVOID dwTemp = NULL;

		if ((0 == ZwMapViewOfSection(m_hFileMapping, NtCurrentProcess(), &dwTemp, 0, 0, &cbSectionOffset, &nViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE))
			&& dwTemp) 
		{
			pDwm->pDrawList = (PDRWARR)dwTemp;
			RtlSecureZeroMemory(dwTemp, sizeof(DRAWARR));
			bRet = TRUE;
		}
         ZwClose(m_hFileMapping);
    }
	else 
	{
		bRet = TRUE;
	}

    return bRet;
}

BOOL DwmStartDraw(HWND target)
{

	BOOL nRet = FALSE;
	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return nRet;

	if (target && !pDrawList->hTarget)
	{
		pDrawList->hTarget = target;
		SetTargetWindowsPos(target);
	}


    if ((pDrawList->m_DrawCount == 0) && pDrawList->m_Draw == false)
    {
        return true;
    }

	return false;

}

BOOL SetTargetWindowsPos(HWND target)
{

	BOOL nRet = FALSE;
	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return nRet;


	//返回窗口左顶点 x,y
	//RECT rect;


	WINDOWINFO wo = { 0 };

	wo.cbSize = sizeof(WINDOWINFO);


	if (GetWindowInfo(target, &wo))
	{

		pDrawList->window_x = wo.rcClient.left; 
		pDrawList->window_y = wo.rcClient.top;


		//返回窗口的大小
		pDrawList->window_w = wo.rcClient.right - wo.rcClient.left;
		pDrawList->window_h = wo.rcClient.bottom - wo.rcClient.top;

		nRet = TRUE;
	}
	return nRet;
}


VOID DwmEndDraw()
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;
    pDrawList->m_Draw = true;
}

VOID draw_line(float X1, float Y1, float X2, float Y2, ImVec4* Color, float thickness)
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;

	if (pDrawList->hTarget)
	{
		X1 += pDrawList->window_x;
		Y1 += pDrawList->window_y;
		X2 += pDrawList->window_x;
		Y2 += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X1,(LONG)Y1 })&&IsPointInWindowsRect({ (LONG)X2,(LONG)Y2 }))
		{
	         pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = Line_M;
             DrawLineStr& Line = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.Line;
             Line.m_X1 = X1;
             Line.m_Y1 = Y1;
             Line.m_X2 = X2;
             Line.m_Y2 = Y2;
             memcpy_(&Line.m_Color, Color, sizeof(ImVec4));
             Line.thickness = thickness;
	         pDrawList->m_DrawCount++;
		}
	}
}

VOID draw_rect(float X, float Y, float W, float H, ImVec4* color, int T)
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;
	
	if (pDrawList->hTarget) 
	{
		X += pDrawList->window_x;
		Y += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X,(LONG)Y }))
		{
	        pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = Rect_M;
            DrawRectStr& Rect = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.Rect;
            Rect.m_X = X;
            Rect.m_Y = Y;
            Rect.m_W = W;
            Rect.m_H = H;
            memcpy_(&Rect.m_Color, color, sizeof(ImVec4));
            Rect.m_thickness = (float)T;
	        pDrawList->m_DrawCount++;
	    }
	}
}

VOID DrawFilledRect(float X, float Y, float W, float H, ImVec4* color, int T)
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;
	
	if (pDrawList->hTarget) 
	{
		X += pDrawList->window_x;
		Y += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X,(LONG)Y }))
		{
	        pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = FilledRect_M;
			DrawFilledRectStr& FilledRect = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.FilledRect;
			FilledRect.m_X = X;
			FilledRect.m_Y = Y;
			FilledRect.m_W = W;
			FilledRect.m_H = H;
            memcpy_(&FilledRect.m_Color, color, sizeof(ImVec4));
	        pDrawList->m_DrawCount++;
	    }
	}
}


VOID DrawCircleFilled(float X, float Y, float Radius, ImVec4* Color, int Segments)
{
	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;

	if (pDrawList->hTarget)
	{
		X += pDrawList->window_x;
		Y += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X,(LONG)Y }))
		{
	        pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = CircleFill_M;
            DrawCircleFillStr& CircleFill = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.CircleFill;
            CircleFill.m_X = X;
            CircleFill.m_Y = Y;
            CircleFill.m_Radius = Radius;
            memcpy_(&CircleFill.m_Color, Color, sizeof(ImVec4));
            CircleFill.m_Segments = Segments;
	        pDrawList->m_DrawCount++;
		}
	}

	
}

VOID DrawCircle(float X, float Y, float Radius, ImVec4* Color, int Segments, float thickness)
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;
	if (pDrawList->hTarget)
	{
		X +=pDrawList->window_x;
		Y += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X,(LONG)Y }))
		{
	        pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = Circle_M;
            DrawCircleStr& Circle = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.Circle;
            Circle.m_X = X;
            Circle.m_Y = Y;
            Circle.m_Radius = Radius;
            memcpy_(&Circle.m_Color, Color, sizeof(ImVec4));
            Circle.m_Segments = Segments;
            Circle.m_thickness = thickness;
	        pDrawList->m_DrawCount++;
		}
	}

	
}
VOID draw_text(float X, float Y, ImVec4* col, const char * text)
{

	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return ;

	if (pDrawList->hTarget)
	{
		X += pDrawList->window_x;
		Y += pDrawList->window_y;
		if (IsPointInWindowsRect({ (LONG)X,(LONG)Y }))
		{
	        pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].m_DrawType = Text_M;
            DrawTextStr& Text = pDrawList->m_DrawInfoArr[pDrawList->m_DrawCount].From.Text;
            Text.m_X = X;
            Text.m_Y = Y;
			memcpy_(&Text.m_Color, col, sizeof(ImVec4));
            Text.m_Outlined = false;
			memcpy_(Text.m_Str, text, strlen(text));
	        pDrawList->m_DrawCount++;
		}
	}
	return;
}

BOOL IsPointInWindowsRect(POINT target_pos)
{

	BOOL nRet = FALSE;
	PDRWARR pDrawList = GetPointer();
	if (!pDrawList) return nRet;
	LONG m_window_x = pDrawList->window_x;
	LONG m_window_y = pDrawList->window_y;
	LONG m_window_w = pDrawList->window_w;
	LONG m_window_h = pDrawList->window_h;


	if ((target_pos.x > m_window_x) && (target_pos.y > m_window_y) && (target_pos.x < (m_window_x + m_window_w)) &&
		(target_pos.y < (m_window_y + m_window_h)))
	{
		return TRUE;
	}

	return nRet;
}





void *__cdecl memcpy_(void *dest, const void *src, size_t num) 
{

    __movsb(static_cast<unsigned char *>(dest), static_cast<const unsigned char *>(src), num);
    return dest;
}

PDRWARR GetPointer()
{
	return ((pdwm_pointer)DWM_DATA_BASE)->pDrawList;
}




DWORD __stdcall ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	DWORD n = 0;
    pdwm_pointer pDwm = (pdwm_pointer)DWM_DATA_BASE;
	pDwm->nNtFunIndex =0x28;
    t_ZwMapViewOfSection ZwMapViewOfSection = (t_ZwMapViewOfSection)&shellSysCall64;
	n = ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	pDwm->nNtFunIndex = 0;
	return n;
}

NTSTATUS __stdcall ZwClose(HANDLE Handle)
{
   	DWORD n = 0;
    pdwm_pointer pDwm = (pdwm_pointer)DWM_DATA_BASE;
	pDwm->nNtFunIndex = 0xf;
    t_ZwClose ZwClose = (t_ZwClose)&shellSysCall64;
	n = ZwClose(Handle);
	pDwm->nNtFunIndex = 0;
    return n;
}