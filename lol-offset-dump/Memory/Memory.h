#pragma once
#include <Windows.h>
#include <malloc.h>
#include <string>
#include <iostream>
#include <vector>
#include <ctype.h>

enum InputType : INT
{
	TYPE_INVALID,
	TYPE_OFFSET,
	TYPE_ADDRESS,
	TYPE_ADDRESS_FUNCTION
};

struct PatternStruct
{
	std::string name, pattern;
	int32_t offset, type_size;
	InputType type;
};

class CMemory
{
public:
	CMemory();
	~CMemory();

	bool Initialize(const char* path_to_exe);

	DWORD Pattern(PatternStruct Struct);

private:
	HANDLE hFileModule;
	DWORD dwFileSize;
	PBYTE rangeStart;
	DWORD ImageBase;
};

