
int __stdcall entry(void*hDllHandle, int dwReason, void*lpreserved) { return 1; }
#pragma comment(linker, "/entry:entry")
