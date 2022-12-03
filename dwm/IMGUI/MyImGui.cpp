#include "MyImGui.h"
#include <string>

//主要是 为这四个指针赋值
IDXGISwapChain* g_pSwapChain;
ID3D11Device* g_pd3dDevice;
ID3D11DeviceContext* g_pd3dDeviceContext;
ID3D11RenderTargetView* g_mainRenderTargetView;
std::string AnisToUTF8(const std::string& Str)
{
	int nwLen = ::MultiByteToWideChar(CP_ACP, 0, Str.c_str(), -1, NULL, 0);

	wchar_t* pwBuf = new wchar_t[(size_t)nwLen + 1];
	ZeroMemory(pwBuf, (size_t)nwLen * 2 + 2);
	::MultiByteToWideChar(CP_ACP, 0, Str.c_str(), Str.length(), pwBuf, nwLen);
	int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
	char* pBuf = new char[(size_t)nLen + 1];
	ZeroMemory(pBuf, (size_t)nLen + 1);
	::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
	std::string retStr(pBuf);
	delete[]pwBuf;
	delete[]pBuf;
	pwBuf = NULL;
	pBuf = NULL;
	return retStr;
}
bool ImGuiDx11_init(IDXGISwapChain* pSwapChain, ID3D11Device* pd3dDevice,HWND hWnd)
{
	g_pSwapChain = pSwapChain;
	g_pd3dDevice = pd3dDevice;
	g_pd3dDevice->GetImmediateContext(&g_pd3dDeviceContext);

	//Create Render Target
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	if (pBackBuffer == nullptr)
	{
		return false;
	}
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
	pBackBuffer->Release();

	// Setup Dear ImGui context
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	// Setup Dear ImGui style
	ImGui::StyleColorsDark();

	// Setup Platform/Renderer bindings
	ImGui_ImplWin32_Init(hWnd); //在这个窗口绘制
	ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

	// Load Fonts
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.IniFilename = nullptr;
	io.LogFilename = nullptr;
	ImGui::StyleColorsDark();
	//GetGlyphRangesChineseFull
	ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\simhei.ttf", 16.0f, NULL, io.Fonts->GetGlyphRangesChineseFull());
	return true;
}

VOID DrawNewText(float X, float Y, ImVec4 Color, bool Outlined, const char* Str)
{
	//CHAR Buffer[1024];
	//ZeroMemory(&Buffer, sizeof(Buffer));
	//va_list va_alist;
	//va_start(va_alist, Str);
	//vsprintf_s(Buffer, Str, va_alist);
	//va_end(va_alist);
	std::string UTF8 = AnisToUTF8(std::string(Str));
	if (Outlined)
	{
		ImU32 c = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
		ImGui::GetOverlayDrawList()->AddText(ImVec2(X + 1.0f, Y + 1.0f), c, UTF8.c_str());
	}
	ImGui::GetOverlayDrawList()->AddText(ImVec2(X, Y), ImGui::ColorConvertFloat4ToU32(Color), UTF8.c_str());
}

VOID DrawNewTextStr(float X, float Y, ImVec4 Color, bool Outlined, const char* Str)
{

	//std::string UTF8 = AnisToUTF8(std::string(Str));
	if (Outlined)
	{
		ImU32 c = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
		ImGui::GetOverlayDrawList()->AddText(ImVec2(X + 1.0f, Y + 1.0f), c, Str);
	}
	ImGui::GetOverlayDrawList()->AddText(ImVec2(X, Y), ImGui::ColorConvertFloat4ToU32(Color), Str);
}

VOID DrawCircleFilled(float X, float Y, float Radius, ImVec4 Color, int Segments)
{
	ImGui::GetOverlayDrawList()->AddCircleFilled(ImVec2(X, Y), Radius, ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), Segments);
}

VOID DrawCircle(float X, float Y, float Radius, ImVec4 Color, int Segments, float thickness)
{
	ImGui::GetOverlayDrawList()->AddCircle(ImVec2(X, Y), Radius, ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), Segments, thickness);
}

VOID DrawRect(float X, float Y, float W, float H, ImVec4 Color, float thickness)
{
	ImGui::GetOverlayDrawList()->AddRect(ImVec2(X, Y), ImVec2(X + W, Y + H),
		ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), 0, 0, thickness);
}

VOID DrawRectEx(float X, float Y, float W, float H, ImVec4 Color, float thickness)
{
	float _W = W / 4.5f, _H = H / 3.5f;
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X, Y), ImVec2(X + _W, Y), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X, Y), ImVec2(X, Y + _H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X + W - _W, Y), ImVec2(X + W, Y), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X + W, Y), ImVec2(X + W, Y + _H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X, Y + H), ImVec2(X + _W, Y + H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X, Y + H), ImVec2(X, Y + H - _H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X + W - _W, Y + H), ImVec2(X + W, Y + H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X + W, Y + H), ImVec2(X + W, Y + H - _H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
}

VOID DrawFilledRect(float X, float Y, float W, float H, ImVec4 Color)
{
	ImGui::GetOverlayDrawList()->AddRectFilled(ImVec2(X, Y), ImVec2(X + W, Y + H), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), 0, 0);
}

VOID DrawLine(float X1, float Y1, float X2, float Y2, ImVec4 Color, float thickness)
{
	ImGui::GetOverlayDrawList()->AddLine(ImVec2(X1, Y1), ImVec2(X2, Y2), ImGui::ColorConvertFloat4ToU32(ImVec4(Color)), thickness);
}
VOID GetFps(_Out_ float fps) {
	fps = ImGui::GetIO().Framerate;
}