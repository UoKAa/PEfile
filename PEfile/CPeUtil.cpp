#include "CPeUtil.h"

CPeUtil::CPeUtil()
{
	FileBuff = NULL;
	FileSize = 0;
	pDosHeader = NULL;
	pNtHeader = NULL;
	pFileHeader = NULL;
	pOptionHeader = NULL;
}

CPeUtil::~CPeUtil()
{
	if (FileBuff)
	{
		delete[]FileBuff;
		FileBuff = NULL;
	}
}

BOOL CPeUtil::LoadFile(const char* patch)
{
	HANDLE hFile = CreateFileA(patch, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile==0)
	{
		return FALSE;
	}
	FileSize = GetFileSize(hFile, 0);
	FileBuff = new char[FileSize] {0};
	DWORD realReadBytes = 0;
	BOOL readSuccess = ReadFile(hFile, FileBuff, FileSize, &realReadBytes, 0);
	if (readSuccess==0)
	{
		return FALSE;
	}
	if (InitPeInfo())
	{
		CloseHandle(hFile);
		return TRUE;
	}
	return FALSE;
}

BOOL CPeUtil::InitPeInfo()
{
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuff;
	if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		printf("����PE�ļ���\n");
		return FALSE;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + FileBuff);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	pFileHeader = &pNtHeader->FileHeader;
	pOptionHeader = &pNtHeader->OptionalHeader;


	return TRUE;
}

void CPeUtil::PrintSectionHeaders()
{
	PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy_s(name, 9, pSectionHeaders->Name, 8);
		printf("��������%s\n", name);
		pSectionHeaders++;
	}
}

//����������
void CPeUtil::GetExportTable()
{
	IMAGE_DATA_DIRECTORY directory = pOptionHeader->DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY pexport = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(directory.VirtualAddress) + FileBuff);
	char* dllName = RvaToFoa(pexport->Name) + FileBuff;
	printf("�ļ����ƣ�%s\n", dllName);
	DWORD* funaddr = (DWORD*)(RvaToFoa(pexport->AddressOfFunctions) + FileBuff);
	WORD* peot = (WORD*)(RvaToFoa(pexport->AddressOfNameOrdinals) + FileBuff);
	DWORD* pent = (DWORD*)(RvaToFoa(pexport->AddressOfNames) + FileBuff);
	for (int i = 0; i < pexport->NumberOfFunctions; i++)
	{
		printf("������ַΪ��%x\t", *funaddr);
		for (int j = 0; j < pexport->NumberOfNames; j++)
		{
			if (peot[j] == i)
			{
				char* funName = RvaToFoa(pent[j]) + FileBuff;
				printf("��������Ϊ��%s\n", funName);
				break;
			}
		}
		funaddr++;
	}
}

//RvaתFoa
DWORD CPeUtil::RvaToFoa(DWORD rva)
{
	//���ݵ�FOA = ���ݵ�RVA-���ε�RVA+���ε�FOA
	PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if ((rva >= pSectionHeaders->VirtualAddress) && (rva < pSectionHeaders->VirtualAddress + pSectionHeaders->Misc.PhysicalAddress))
		{
			return rva - pSectionHeaders->VirtualAddress + pSectionHeaders->PointerToRawData;
		}
		pSectionHeaders++;
	}
	return 0;
}
