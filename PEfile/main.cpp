#include<iostream>
#include"CPeUtil.h"

int main()
{
	CPeUtil peUtil;
	BOOL ifSuccess = peUtil.LoadFile("D://Software//Game//M01//dbghelp.dll");
	if (ifSuccess)
	{
		peUtil.PrintSectionHeaders();
		peUtil.GetExportTable();
		peUtil.GetImportTable();
		return 0;
	}
	else
	{
		printf("����PE�ļ�ʧ�ܣ�\n");
	}
	
	return 0;
}