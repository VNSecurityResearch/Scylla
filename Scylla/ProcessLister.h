#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <memory>
#include <psapi.h>

#include "NativeWinApi.h"
#include "DeviceNameResolver.h"

typedef BOOL (WINAPI *def_IsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

class Process {
public:
	DWORD PID;
  DWORD sessionId;
	DWORD_PTR imageBase;
  DWORD_PTR pebAddress;
	DWORD entryPoint; // RVA without image base
	DWORD imageSize;
	WCHAR filename[MAX_PATH];
	WCHAR fullPath[MAX_PATH];

  Process() : PID{ 0 } {};
	/*{
		PID = 0;
	}*/
};

enum ProcessType {
	PROCESS_UNKNOWN,
	PROCESS_MISSING_RIGHTS,
	PROCESS_32,
	PROCESS_64
};

class ProcessLister {
public:

	static def_IsWow64Process _IsWow64Process;

	ProcessLister()
	{
		//deviceNameResolver = new DeviceNameResolver();
    deviceNameResolver = std::make_shared<DeviceNameResolver>();

		_IsWow64Process = (def_IsWow64Process)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
	}

	~ProcessLister()
	{
		//delete deviceNameResolver;
	}

	auto getProcessList () const -> const std::vector<Process>&;
	static bool isWindows64();
	static DWORD setDebugPrivileges();
  auto getProcessListSnapshotNative () -> const std::vector<Process>&;

private:
	
  std::vector<Process> processList;

	//DeviceNameResolver * deviceNameResolver;
  std::shared_ptr<DeviceNameResolver> deviceNameResolver;

	ProcessType checkIsProcess64(HANDLE hProcess);

	bool getAbsoluteFilePath(HANDLE hProcess, Process * process);

  void handleProcessInformationAndAddToList(PSYSTEM_PROCESS_INFORMATION pProcess);
  void getProcessImageInformation(HANDLE hProcess, Process* process);
  DWORD_PTR getPebAddressFromProcess(HANDLE hProcess);
};