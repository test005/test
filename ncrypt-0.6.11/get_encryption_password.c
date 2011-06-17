#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "get_encryption_password.h"
#include "read_pass.h"
#include "mem.h"

char* const get_encryption_password()
{
    char* pass1 = NULL;
    char* pass2 = NULL;
    /* if we are encrypting, ask for password twice */
    int i=0;
    while(1)
    {
    if(i>2)
    {
        fprintf(stderr,"The password must be entered in correctly.\n");
        exit(-1);
    }
    pass1 = read_pass("Enter encryption password: ");
    if(pass1 == NULL) exit(-1);
    pass2 = read_pass("Re-enter encryption password: ");
    if(pass2 == NULL) exit(-1);
    if(strcmp(pass1,pass2))
    {
        fprintf(stderr,"Passwords do not match!\n");
        i++;
        continue;
    }
    /* erase one of the plaintext password instances from memory
     * as soon as we check the two instances against each other
     */
    // while(*pass2) *pass2++ = 0;
    guaranteed_memset(pass2,0,strlen(pass1));
    break;
    }
    return pass1;
}

