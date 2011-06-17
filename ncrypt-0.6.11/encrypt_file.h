#ifndef _encrypt_file_h_
#define _encrypt_file_h_

#include <stdio.h>
#include "mem.h"

void encrypt_file (FILE* input, long int fsize, FILE* output, int algo);

#endif

