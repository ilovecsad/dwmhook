#pragma once
#include "pch.h"
#include "searchSign.h"


typedef struct
{
	 DWORD64 orgPresentDWM;
	 DWORD64 jmpOrgPresentDWM;
	 DWORD64 orgPresentDWM2;
	 DWORD64 jmpOrgPresentDWM2;

	 DWORD64 orgGetBuffer; 
	 DWORD64 jmpOrgGetBuffer; 


}dxgi_fun;

typedef struct {


	 DWORD64 pCallPresentMultiplaneOverlay;
	 DWORD64 jmppCallPresentMultiplaneOverlay;

}d2d1_fun;


class work
{
public:
	
	work()
	{

	}
	~work()
	{

	}
public:
	BOOL initPtr();

	BOOL HookVmmvareMachine();
	BOOL HookVmmvareMachine2();

	BOOL HookPhysicalMachine();

	void printfStackFrame(char* szSign);
};


extern dxgi_fun g_dxgi;
extern d2d1_fun g_d2d1;
extern work* g_work;