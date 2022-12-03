#pragma once
#include "importfun.h"
#include <Windows.h>

#define BUF_LEN 256
#define MAX_DRAW 500
#define MAPNAME L"hzw_dwm"


struct ImVec4
{
	float  x, y, z, w;
};




struct DrawTextStr
{
	float	m_X;
	float	m_Y;
	ImVec4	m_Color;
	bool	m_Outlined;
	char	m_Str[BUF_LEN];
};
struct DrawCircleFillStr
{
	float		m_X;
	float		m_Y;
	float		m_Radius;
	ImVec4		m_Color;
	int		m_Segments;
};
struct DrawCircleStr
{
	float		m_X;
	float		m_Y;
	float		m_Radius;
	ImVec4		m_Color;
	int		m_Segments;
	float m_thickness;
};
struct DrawRectStr
{
	float m_X;
	float m_Y;
	float m_W;
	float m_H;
	ImVec4 m_Color;
	float m_thickness;
};
struct DrawRectExStr
{
	float m_X;
	float m_Y;
	float m_W;
	float m_H;
	ImVec4	m_Color;
	float	m_thickness;
};
struct DrawFilledRectStr
{
	float m_X;
	float m_Y;
	float m_W;
	float m_H;
	ImVec4	m_Color;
};
struct DrawLineStr
{
	float m_X1;
	float m_Y1;
	float m_X2;
	float m_Y2;
	ImVec4	m_Color;
	float thickness;
};
struct FPS {
	float Fps;
};
enum DRAWTYPE { Text_M, Text2_M, CircleFill_M, Circle_M, Rect_M, RectEx_M, FilledRect_M, Line_M, FPS_M };
struct DrawInfo
{
	DRAWTYPE m_DrawType;
	union
	{
		DrawTextStr			Text;
		DrawCircleFillStr	CircleFill;
		DrawCircleStr		Circle;
		DrawRectStr			Rect;
		DrawRectExStr		RectEx;
		DrawFilledRectStr	FilledRect;
		DrawLineStr			Line;
		FPS					Fps;
	}From;
};
typedef struct DrawArr
{
	PVOID pDrawList;   //保存自己
	HWND hTarget;        //目的的窗口句柄
	LONG window_x;       //窗口 X
	LONG window_y;
	LONG window_w;       
	LONG window_h;
	bool		m_Draw;
	int			m_DrawCount;
	BYTE m_keyState[0x100];
	DrawInfo	m_DrawInfoArr[MAX_DRAW];

}DRAWARR, *PDRWARR;

typedef struct
{
	DWORD64 nNtFunIndex;
	PDRWARR pDrawList;
}*pdwm_pointer;

#define DWM_DATA_BASE  (ULONG_PTR)(__readgsqword(0x60)+0xc00) //当你修改这个的时候 记得把 asm也修改啊


PVOID SysCall();
BOOL InitDwm();
BOOL DwmStartDraw(HWND target);
VOID DwmEndDraw();
BOOL SetTargetWindowsPos(HWND target);
VOID draw_text(float X, float Y, ImVec4* col, const char* text);
VOID DrawCircle(float X, float Y, float Radius, ImVec4* Color, int Segments, float thickness);
VOID DrawCircleFilled(float X, float Y, float Radius, ImVec4* Color, int Segments);
VOID draw_rect(float X, float Y, float W, float H, ImVec4* color, int T);
VOID draw_line(float X1, float Y1, float X2, float Y2, ImVec4* Color, float thickness);
VOID DrawFilledRect(float X, float Y, float W, float H, ImVec4* color, int T);
BOOL IsPointInWindowsRect(POINT target_pos);
void* __cdecl memcpy_(void* dest, const void* src, size_t num);
PDRWARR GetPointer();



DWORD __stdcall ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
NTSTATUS __stdcall ZwClose(HANDLE Handle);

