// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"


work* g_work = NULL;
hook* g_hook = NULL;




DWORD threadWork(PVOID p)
{
	g_work = new work();
	g_hook = new hook();
	g_exceptionhook = new exceptionhook();

	if (!g_work->initPtr())return 0;
	
	//g_work->HookVmmvareMachine();
	g_work->HookPhysicalMachine();
	

	return 0;
}


