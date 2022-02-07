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
		printf("不是PE文件！\n");
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
		printf("区段名：%s\n", name);
		pSectionHeaders++;
	}
}

//解析导出表
void CPeUtil::GetExportTable()
{
	IMAGE_DATA_DIRECTORY directory = pOptionHeader->DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY pexport = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(directory.VirtualAddress) + FileBuff);
	char* dllName = RvaToFoa(pexport->Name) + FileBuff;
	printf("文件名称：%s\n", dllName);
	DWORD* funaddr = (DWORD*)(RvaToFoa(pexport->AddressOfFunctions) + FileBuff);
	WORD* peot = (WORD*)(RvaToFoa(pexport->AddressOfNameOrdinals) + FileBuff);
	DWORD* pent = (DWORD*)(RvaToFoa(pexport->AddressOfNames) + FileBuff);
	for (int i = 0; i < pexport->NumberOfFunctions; i++)
	{
		printf("函数地址：%x\t", *funaddr);
		for (int j = 0; j < pexport->NumberOfNames; j++)
		{
			if (peot[j] == i)
			{
				char* funName = RvaToFoa(pent[j]) + FileBuff;
				printf("函数名称：%s\n", funName);
				break;
			}
		}
		funaddr++;
	}
}

void CPeUtil::GetImportTable()
{
	IMAGE_DATA_DIRECTORY directory = pOptionHeader->DataDirectory[1];
	//导入表地址
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(directory.VirtualAddress) + FileBuff);
	while (pImport->OriginalFirstThunk)
	{
		char* dllName = RvaToFoa(pImport->Name) + FileBuff;
		printf("DLL文件名称：%s\n", dllName);
		printf("TimeDataStamp = %d\n", pImport->TimeDateStamp);
		PIMAGE_THUNK_DATA pThukData = (PIMAGE_THUNK_DATA)(RvaToFoa(pImport->OriginalFirstThunk) + FileBuff);
		while (pThukData->u1.Function)
		{
			//判断是否是按序号导入
			if (pThukData->u1.Ordinal & 0x80000000)
			{
				printf("按序号导入：%d\n", pThukData->u1.Ordinal & 0x7FFFFFFF);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pThukData->u1.AddressOfData) + FileBuff);
				printf("按名称导入：%s\n", importName->Name);
			}
			pThukData++;
		}
		printf("\n");
		pImport++;
	}
}

//Rva转Foa
DWORD CPeUtil::RvaToFoa(DWORD rva)
{
	//数据的FOA = 数据的RVA-区段的RVA+区段的FOA
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
