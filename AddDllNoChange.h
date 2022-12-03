#pragma once
#include <Windows.h>
#include <Psapi.h>

#include <vector>
using namespace std;
typedef struct
{
	DWORD   VirtualAddress; //记录节区开始的位置
	DWORD   VirtualSize;    //记录节区的大小
	DWORD   nProtection;
}sectionData;
class AddDllNoChange
{
public:
	AddDllNoChange();
	~AddDllNoChange();
	BOOL WINAPI AddNoChange(MODULEINFO* pInfo);
	DWORD calcTextSize(MODULEINFO* pInfo,vector<sectionData>& pSectionData);
	BOOL EnterLock();
	BOOL LeaveLock(VOID);
private:
	
	ULONG BBCastSectionProtection(IN ULONG characteristics, IN BOOLEAN noDEP);
	VOID suspendAllThread(BOOL bsuspend);
	DWORD calcTextSize(PIMAGE_NT_HEADERS pNtHeaders);
private:

};

