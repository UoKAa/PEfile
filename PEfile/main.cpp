#include<iostream>
#include"CPeUtil.h"

int main()
{
	CPeUtil peUtil;
	BOOL ifSuccess = peUtil.LoadFile("D://Software//Game//M01//KartRecovery.exe");
	if (ifSuccess)
	{
		peUtil.PrintSectionHeaders();
		peUtil.GetExportTable();
		return 0;
	}
	else
	{
		printf("����PE�ļ�ʧ�ܣ�\n");
	}
	
	return 0;
}