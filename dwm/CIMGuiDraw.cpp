#include "CIMGuiDraw.h"
#include "searchSign.h"

#define 红色 ImVec4(1.0f, 0.0f, 0.0f, 1.0f)
#define 黑色 ImVec4(0.0f, 0.0f, 0.0f, 1.0f)
#define 白色 ImVec4{ 1.0f, 1.0f, 1.0f, 1.0f }
volatile LONG g_isLocked = FALSE;



CIMGuiDraw::CIMGuiDraw()
{
}

CIMGuiDraw::~CIMGuiDraw()
{
}

bool CIMGuiDraw::InitMiGuiDx11Hook(IDXGISwapChain* pSwapChain, ID3D11Device* pd3dDevice,HWND hwnd)
{
	return ImGuiDx11_init(pSwapChain, pd3dDevice,hwnd);
}

void CIMGuiDraw::CleanupRenderTarget()
{
	 if (g_mainRenderTargetView) { 
		int a = g_mainRenderTargetView->Release(); 
		 g_mainRenderTargetView = NULL; 
		 ck_printf("hzw:CleanupRenderTarget 成功 %d",a);
	 }
}

void CIMGuiDraw::CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer = NULL;
	if (S_OK == g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) 
	{
		int  a = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
		pBackBuffer->Release();
		ck_printf("hzw:CreateRenderTarget  g_mainRenderTargetView 成功 %d pBackBuffer[%p] ",a,pBackBuffer);
	}
}



void CIMGuiDraw::ImGuiDx11Draw()
{

	
	//当前数组 图形数量检查
	if ((m_pDrawAll->m_Draw != true))
	{
		return;
	}

	//begin
	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();


	//画所有图形
	for (int i = 0; i < m_pDrawAll->m_DrawCount; i++)
	{
		switch (m_pDrawAll->m_DrawInfoArr[i].m_DrawType)
		{
		case Text_M:
		{
			DrawTextStr& Text = m_pDrawAll->m_DrawInfoArr[i].From.Text;
			DrawNewText(Text.m_X, Text.m_Y, Text.m_Color, Text.m_Outlined, Text.m_Str);
		}
		break;
		case Text2_M:
		{
			DrawTextStr& Text = m_pDrawAll->m_DrawInfoArr[i].From.Text;
			DrawNewTextStr(Text.m_X, Text.m_Y, Text.m_Color, Text.m_Outlined, Text.m_Str);
		}
		break;
		case CircleFill_M:
		{
			DrawCircleFillStr& CircleFill = m_pDrawAll->m_DrawInfoArr[i].From.CircleFill;
			DrawCircleFilled(CircleFill.m_X, CircleFill.m_Y, CircleFill.m_Radius, CircleFill.m_Color, CircleFill.m_Segments);
		}
		break;
		case Circle_M:
		{
			DrawCircleStr& Circle = m_pDrawAll->m_DrawInfoArr[i].From.Circle;
			DrawCircle(Circle.m_X, Circle.m_Y, Circle.m_Radius, Circle.m_Color, Circle.m_Segments, Circle.m_thickness);
		}
		break;
		case Rect_M:
		{
			DrawRectStr& Rect = m_pDrawAll->m_DrawInfoArr[i].From.Rect;
			DrawRect(Rect.m_X, Rect.m_Y, Rect.m_W, Rect.m_H, Rect.m_Color, Rect.m_thickness);
		}
		break;
		case RectEx_M:
		{
			DrawRectExStr& RectEx = m_pDrawAll->m_DrawInfoArr[i].From.RectEx;
			DrawRectEx(RectEx.m_X, RectEx.m_Y, RectEx.m_W, RectEx.m_H, RectEx.m_Color, RectEx.m_thickness);
		}
		break;
		case FilledRect_M:
		{
			DrawFilledRectStr& FilledRect = m_pDrawAll->m_DrawInfoArr[i].From.FilledRect;
			DrawFilledRect(FilledRect.m_X, FilledRect.m_Y, FilledRect.m_W, FilledRect.m_H, FilledRect.m_Color);
		}
		break;
		case Line_M:
		{
			DrawLineStr& Line = m_pDrawAll->m_DrawInfoArr[i].From.Line;
			DrawLine(Line.m_X1, Line.m_Y1, Line.m_X2, Line.m_Y2, Line.m_Color, Line.thickness);
		}
		break;
		case FPS_M:
		{
			FPS& Fps = m_pDrawAll->m_DrawInfoArr[i].From.Fps;
			GetFps(Fps.Fps);
		}
		break;
		default:
			break;
		}
	}



	//画图标志检查
	m_pDrawAll->m_DrawCount = 0;
	m_pDrawAll->m_Draw = false;


	//end
	ImGui::Render();
	g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	

}

void CIMGuiDraw::ImGuiDx11DrawTestDemo()
{
	if (!g_pSwapChain)return;
	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	DrawNewText(150, 150, 红色, false, "testDemo");
	DrawRect(100, 100, 300, 300, 红色, 1);

	ImGui::Render();
	g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	//g_pSwapChain->Present(1, 0); 
	
}

bool CIMGuiDraw::InitMessage()
{
	bool flag = false;

	//共享内存
	if (InitFileMapping() /*&& InitDwmShellcodeMapping()*/)
	{
		flag = true;
	}

	return flag;
}

PDRWARR CIMGuiDraw::GetPointer()
{
	return m_pDrawAll;
}


bool CIMGuiDraw::InitFileMapping()
{
	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	HANDLE hFileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(DRAWARR), MAPNAME);
	if (hFileMapping == NULL)
	{
		ck_printf("hzw:OpenFileMappingA:%d\n", GetLastError());
		return false;
	}
	m_pDrawAll = (PDRWARR)MapViewOfFile(hFileMapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (m_pDrawAll )
	{
		RtlSecureZeroMemory(m_pDrawAll, sizeof(DRAWARR));

		ck_printf("hzw:初始化DWM绘制数据成功 数据句柄 %x\n",hFileMapping);
		return true;
	}

	return false;
}
/*
bool CIMGuiDraw::InitDwmShellcodeMapping()
{
	PVOID pAllcoateShellcode = NULL;
	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	HANDLE hFileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,PAGE_EXECUTE_READWRITE, 0, sizeof(dwm_method_shellcode), MAPNAME2);
	if (hFileMapping == NULL)
	{
		ck_printf("hzw:初始化DWMshellcode失败:%d\n", GetLastError());
		return false;
	}
	pAllcoateShellcode = MapViewOfFile(hFileMapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (pAllcoateShellcode)
	{
		RtlSecureZeroMemory(pAllcoateShellcode, sizeof(dwm_method_shellcode));
		RtlCopyMemory(pAllcoateShellcode, dwm_method_shellcode, sizeof(dwm_method_shellcode));
		if (UnmapViewOfFile(pAllcoateShellcode))
		{
			ck_printf("hzw:初始化DWMshellcode成功 shellcode句柄 %x\n",hFileMapping);
			return true;
		}
	}

	
	return false;
}
*/




