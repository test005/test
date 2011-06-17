/*
 * mem.c - routines for cleaning up in memory
 */
#include <stdio.h>

void *guaranteed_memset(void *v,int c,size_t n)
{ 
	volatile char *p=v; 
	while (n--) *p++=c; 
	return v; 
}
