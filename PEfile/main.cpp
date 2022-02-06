#include<iostream>
#include"CPeUtil.h"

int main()
{
	CPeUtil peUtil;
	BOOL ifSuccess = peUtil.LoadFile("D://Software//Game//M01//dbghelp.dll");
	if (ifSuccess)
	{
		peUtil.PrintSectionHeaders();
		return 0;
	}
	else
	{
		printf("¼ÓÔØPEÎÄ¼þÊ§°Ü£¡\n");
	}
	
	return 0;
}