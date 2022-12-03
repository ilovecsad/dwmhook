#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#pragma comment(lib, "D3D11.lib")
extern IDXGISwapChain* g_pSwapChain;
extern ID3D11Device* g_pd3dDevice;
extern ID3D11DeviceContext* g_pd3dDeviceContext;
extern ID3D11RenderTargetView* g_mainRenderTargetView;
//≥ı ºªØIMGUI
bool ImGuiDx11_init(IDXGISwapChain* pSwapChain, ID3D11Device* pd3dDevice,HWND hwnd);
VOID DrawNewText(float X, float Y, ImVec4 Color, bool Outlined, const char* Str);
VOID DrawNewTextStr(float X, float Y, ImVec4 Color, bool Outlined, const char* Str);
VOID DrawCircleFilled(float X, float Y, float Radius, ImVec4 Color, int Segments);
VOID DrawCircle(float X, float Y, float Radius, ImVec4 Color, int Segments, float thickness);
VOID DrawRect(float X, float Y, float W, float H, ImVec4 Color, float thickness);
VOID DrawRectEx(float X, float Y, float W, float H, ImVec4 Color, float thickness);
VOID DrawFilledRect(float X, float Y, float W, float H, ImVec4 Color);
VOID DrawLine(float X1, float Y1, float X2, float Y2, ImVec4 Color, float thickness);
VOID GetFps(_Out_ float fps);