# GhostWriting

A paradox: Writing to another process without openning it nor actually writing to it

The concept
Lots of today’s malicious software (virii, trojans, rootkits, etc.) use remote execution techniques in order to avoid AV software, hide themselves, go resident in more suitable processes and so on.

Remote execution means a process can somehow inject executable code into another process and trigger the execution of said executable code into the context of that process. Injected code can be both, a DLL that gets loaded into the target process or a bunch of code+data bytes directly written into the memory space of the target process.

What we present here is a new way of accomplishing this task of remote code execution or, in more general terms, remote byte injection.

The basic idea of this method is forgetting about this process-centric idea of remote code execution. This is the challenge: writing and running remote code without actually opening the target process. We will not open any process nor will we write to it. Is this a paradox ? No, it is not. It is true that we are not going to use any OpenProcess, DebugActiveProcess, NtOpenProcess or similar functions. We will not even use any WriteProcessMemory, NtWriteVirtualMemory or alike.
