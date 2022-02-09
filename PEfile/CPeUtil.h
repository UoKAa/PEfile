#pragma once
#include<Windows.h>
#include<iostream>

class CPeUtil
{
public:
	CPeUtil();
	~CPeUtil();
	BOOL LoadFile(const char* patch);
	BOOL InitPeInfo();
	void PrintSectionHeaders();
	void GetExportTable();
	void GetImportTable();
private:
	char* FileBuff;
	DWORD FileSize;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionHeader;
	//PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD RvaToFoa(DWORD rva);

};
