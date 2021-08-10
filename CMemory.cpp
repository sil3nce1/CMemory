#pragma once
#include "CMemory.h"

MODULEINFO CMemory::GetModuleInfo(char* szModule)
{
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = GetModuleHandle(szModule);
	if (hModule == 0)
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

PVOID CMemory::FindPattern(char* szModule, char* pattern, char* mask)
{
	MODULEINFO mInfo = GetModuleInfo(szModule);

	uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
	uintptr_t size = (uintptr_t)mInfo.SizeOfImage;

	DWORD patternLength = (DWORD)strlen(mask);

	for (uintptr_t i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		if (IsBadReadPtr((void*)(base + i), patternLength))
		{
			i++;
			continue;
		}
		for (DWORD j = 0; j < patternLength; j++)
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);

		if (found)
			return (PVOID)(base + i);
	}
	return NULL;
}

PVOID CMemory::FindPattern(uintptr_t startAddress, uintptr_t endAddress, char* pattern, char* mask)
{
	uintptr_t size = (uintptr_t)(endAddress - startAddress);
	DWORD patternLength = (DWORD)strlen(mask);

	for (uintptr_t i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		if (IsBadReadPtr((void*)(startAddress + i), patternLength))
		{
			i++;
			continue;
		}
		for (DWORD j = 0; j < patternLength; j++)
			found &= mask[j] == '?' || pattern[j] == *(char*)(startAddress + i + j);

		if (found)
			return (PVOID)(startAddress + i);
	}
	return NULL;
}

std::vector<PVOID> CMemory::FindPatternVec(char* szModule, char* pattern, char* mask)
{
	MODULEINFO mInfo = GetModuleInfo(szModule);

	uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
	uintptr_t size = (uintptr_t)mInfo.SizeOfImage;

	DWORD patternLength = (DWORD)strlen(mask);

	std::vector<PVOID> addressVec;

	for (uintptr_t i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		if (IsBadReadPtr((void*)(base + i), patternLength))
		{
			i++;
			continue;
		}
		for (DWORD j = 0; j < patternLength; j++)
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);

		if (found)
			addressVec.push_back((PVOID)(base + i));
			
	}
	return addressVec;
}

bool CMemory::Hook(char* src, char* dst, unsigned int len)
{
	if (len < 5) return false;

	DWORD oldProtect;
	VirtualProtect((LPVOID)src, len, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset(src, 0x90, len);

	uintptr_t relativeAddress = (uintptr_t)(dst - src - 5);
	*src = (char)0xE9;
	*(uintptr_t*)(src + 1) = (uintptr_t)relativeAddress;

	VirtualProtect((LPVOID)src, len, oldProtect, &oldProtect);
	return true;
}

bool CMemory::PatternHook(char* szModule, char* pattern, char* mask, char* dst, unsigned int len, uintptr_t* jmpAddy)
{
	uintptr_t src = (uintptr_t)FindPattern(szModule, pattern, mask);
	jmpAddy = (uintptr_t*)(src + len);
	return Hook((char*)src, (char*)dst, len);
}

PVOID CMemory::TrampHook(char* src, char* dst, unsigned int len)
{
	char* gateway = (char*)VirtualAlloc(NULL, len + 5, MEM_COMMIT | MEM_RELEASE, PAGE_EXECUTE_READWRITE);
	memcpy(gateway, src, len);
	uintptr_t relativeAddress = (uintptr_t)(gateway - src - 5);
	*(gateway + len) = (char)0xE9;
	*(uintptr_t*)(gateway + len + 1) = (uintptr_t)relativeAddress;

	if (Hook(src, dst, len))
		return gateway;
	else
		return 0;
}

PVOID CMemory::VMTHook(uintptr_t pVTable, char* dst, int index)
{
	uintptr_t dwVTable = *((uintptr_t*)pVTable);
	uintptr_t dwEntry = dwVTable + index;
	uintptr_t dwOrig = *((uintptr_t*)dwEntry);

	DWORD dwOldProtection;
	VirtualProtect((LPVOID)dwEntry, sizeof(dwEntry),
		PAGE_EXECUTE_READWRITE, &dwOldProtection);

	*((uintptr_t*)dwEntry) = (uintptr_t)dst;

	VirtualProtect((LPVOID)dwEntry, sizeof(dwEntry),
		dwOldProtection, &dwOldProtection);

	return (PVOID)dwOrig;
}

void CMemory::PatchMem(uintptr_t address, char* bytes, unsigned int len)
{
	DWORD oldProtect;
	VirtualProtect((LPVOID)address, len, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy((void*)address, (void*)bytes, len);

	VirtualProtect((LPVOID)address, len, oldProtect, &oldProtect);
}

PVOID CMemory::TrampPatternHook(char* szModule, char* pattern, char* mask, char* dst, unsigned int len)
{
	char* src = (char*)FindPattern(szModule, pattern, mask);
	return TrampHook(src, dst, len);
}

