#include "stdafx.h"

BOOL FreeRemoteLibrary(HANDLE hProcess, DWORD hRemoteLibrary) 
{ 
    DWORD dwRemoteThreadId; 
    HANDLE hRemoteThread; 
    BOOL nRet; 
	
    hRemoteThread=CreateRemoteThread(hProcess,NULL,255, 
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary"),(void*)hRemoteLibrary,0,&dwRemoteThreadId); 
	
    if (NULL == hRemoteThread) 
        return FALSE; 
	
    WaitForSingleObject(hRemoteThread,INFINITE); 
    GetExitCodeThread(hRemoteThread,(DWORD*)&nRet); 
    return nRet; 
}


int EnableDebugPriv(const char * name)  
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		&hToken) )
	{
		printf("OpenProcessToken error\n");
		return 1;
	}

	if(!LookupPrivilegeValue(NULL,name,&luid))
	{
		printf("LookupPrivilege error!\n");
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes =SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;

	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL) )
	{
		printf("AdjustTokenPrivileges error!\n");
		return 1;
	}
	return 0;
}


BOOL InjectDll(const char *DllFullPath, const DWORD dwRemoteProcessId) 
{
	HANDLE hRemoteProcess;

	if(EnableDebugPriv(SE_DEBUG_NAME))
	{
		printf("add privilege error");
		return FALSE;
	}

	if((hRemoteProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId))==NULL)
	{
		printf("OpenProcess error\n");
		return FALSE;
	}
	char *pszLibFileRemote;

	pszLibFileRemote=(char *)VirtualAllocEx( hRemoteProcess, 
		NULL, lstrlen(DllFullPath)+1, 
		MEM_COMMIT, PAGE_READWRITE);
	if(pszLibFileRemote==NULL)
	{
		printf("VirtualAllocEx error\n");
		CloseHandle(hRemoteProcess);
		return FALSE;
	}

	if(WriteProcessMemory(hRemoteProcess,
		pszLibFileRemote,(void *)DllFullPath,lstrlen(DllFullPath)+1,NULL) == 0)
	{
		printf("WriteProcessMemory error\n");
		VirtualFreeEx(hRemoteProcess, pszLibFileRemote, 0, MEM_RELEASE);
		CloseHandle(hRemoteProcess);
		return FALSE;
	}

	//PTHREAD_START_ROUTINE pfnStartAddr=(PTHREAD_START_ROUTINE)
	//	GetProcAddress(GetModuleHandle(TEXT("Kernel32")),"LoadLibraryA");
	FARPROC pLoadDll=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryA");
	FARPROC pFreeDll=GetProcAddress(GetModuleHandle("kernel32.dll"),"FreeLibrary");
	PTHREAD_START_ROUTINE pfnStartAddr=(PTHREAD_START_ROUTINE)pLoadDll;
	if(pfnStartAddr == NULL)
	{
		printf("GetProcAddress error\n");
		return FALSE;
	}

	HANDLE hRemoteThread;
	DWORD nRet=NULL; 


	if( (hRemoteThread = CreateRemoteThread(hRemoteProcess,NULL,0, 
		pfnStartAddr,pszLibFileRemote,0,NULL))==NULL)
	{
		printf("CreateRemoteThread error\n");
		return FALSE;
	}

	
	
	while(TRUE) 
	{
		WaitForSingleObject(hRemoteThread,INFINITE);
		GetExitCodeThread(hRemoteThread,&nRet); 
		if (nRet == STILL_ACTIVE)
		{
			Sleep(1000);
		}else{
			break;
		}
	}


	MessageBox(NULL,_TEXT("Successed!!\nNow Begin unload"),_TEXT("Message"),MB_OK);

	//printf("Now Close Remote thread\n");

	if(!FreeRemoteLibrary(hRemoteProcess,nRet))
	{
		printf("Unload  error\n");
		return FALSE;
	}
	VirtualFreeEx(hRemoteProcess, pszLibFileRemote, 0, MEM_RELEASE);
	return TRUE;
}

int main(int argc, char* argv[])
{
	//char Path[255];
	char Exepath[MAX_PATH],DllPath[MAX_PATH],dir[MAX_PATH];
	DWORD Pid;

	
	
	MessageBox(NULL,_TEXT("Inject a [hello.dll] into remote process with given PID and then unload it from remote process."),_TEXT("Zyguo homework(20120221)"),MB_OK);
	if (argc < 2)
	{
		MessageBox(NULL,TEXT("Add a Pid as first argument"),_TEXT("Warning"),MB_OK);
		return 0;
	}
	

	Pid=atoi(argv[1]);

	GetModuleFileName(NULL,Exepath,MAX_PATH);
	_splitpath(Exepath,DllPath,dir,NULL,NULL);
	strcat(DllPath,dir);
	strcat(DllPath,_TEXT("hello.dll"));

	//printf("%d\n",Pid);
	if(!InjectDll(DllPath,Pid))
	{
		MessageBox(NULL,TEXT("Failed"),_TEXT("Warning"),MB_OK);
	}

	return 0;
}

