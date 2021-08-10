#pragma once
#include <windows.h>
#include <vector>
#include <iostream>
#include <psapi.h>


class CMemory {
public:
	static PVOID FindPattern(char* szModule, char* pattern, char* mask);
	static PVOID FindPattern(uintptr_t startAddress, uintptr_t endAddress, char* pattern, char* mask);
	static std::vector<PVOID> FindPatternVec(char* szModule, char* pattern, char* mask);
	static PVOID TrampPatternHook(char* szModule, char* pattern, char* mask, char* dst, unsigned int len);
	static PVOID TrampHook(char* src, char* dst, unsigned int len);
	static PVOID VMTHook(uintptr_t pVTable, char* dst, int index);
	static void PatchMem(uintptr_t address, char* bytes, unsigned int len);
	static bool PatternHook(char* szModule, char* pattern, char* mask, char* dst, unsigned int len, uintptr_t* jmpAddy);
	static bool Hook(char* src, char* dst, unsigned int len);
private:
	static MODULEINFO GetModuleInfo(char* szModule);
};