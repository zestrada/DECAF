/*
 * hypercall.c - issue hypercall number based on argument
 */

#include <stdio.h>
#include <unistd.h>
#include "hypercall.h"

int main (int argc, char *argv[]) {
	int cmd = atoi(argv[1]);
	HYPERCALL0(cmd);
	printf("Made hypercall %x\n", cmd);
}
