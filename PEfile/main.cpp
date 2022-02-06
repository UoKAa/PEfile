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
		printf("¼ÓÔØPEÎÄ¼þÊ§°Ü£¡\n");
	}
	
	return 0;
}