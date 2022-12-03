#pragma once
#include "IMGUI/MyImGui.h"

/*���ֵĳ���*/
#define BUF_LEN 256
/*����������*/
#define MAX_DRAW 500
/*�����ڴ�*/
#define MAPNAME L"hzw_dwm"
#define MAPNAME2 L"method_dwm"
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
/*ͼ������ö��*/
enum DRAWTYPE { Text_M, Text2_M,CircleFill_M, Circle_M, Rect_M, RectEx_M, FilledRect_M, Line_M,FPS_M};

//ͼ�ε���Ϣ
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


//�Ի�ͼ״̬ �Լ����Ķ�������
typedef struct DrawArr
{
	PVOID pDrawList;   //�����Լ�
	HWND hTarget;        //Ŀ�ĵĴ��ھ��
	LONG window_x;       //���� X
	LONG window_y;
	LONG window_w;       
	LONG window_h;
	bool		m_Draw;
	int			m_DrawCount;
	BYTE m_keyState[0x100];
	DrawInfo	m_DrawInfoArr[MAX_DRAW];
}DRAWARR, * PDRWARR;

class CIMGuiDraw
{
public:
	CIMGuiDraw();
	~CIMGuiDraw();
	
public:
	/*
	* �ύ���л�
	*/
	void ImGuiDx11Draw();
	void ImGuiDx11DrawTestDemo();
	bool InitMiGuiDx11Hook(IDXGISwapChain* pSwapChain, ID3D11Device* pd3dDevice,HWND hwnd);
	void  CleanupRenderTarget();
	void CreateRenderTarget();
	/*
	* ��ʼ��ͨѶ m_pDrawAll
	*/
	bool InitMessage();
	PDRWARR GetPointer();

private:
	
	
	/*
	* �����ڴ�
	*/
	bool InitFileMapping();
	bool InitDwmShellcodeMapping();
	/*
	* 
	*/
private:
	PDRWARR m_pDrawAll = nullptr;
};

