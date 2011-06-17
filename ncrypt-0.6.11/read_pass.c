#include "read_pass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>
#include "ncrypt.h"

/*
 * read the password in from the user, returns NULL on an error, based upon
 * sample code in the excellent book "Building Secure Software" by John Viega
 * and Gary McGraw
 */
char *read_pass(char *prompt)
{
    char *buf = (char *)malloc(sizeof(char) * 4096);
    char *res;
    int n;
    int fn = fileno(stdin);
    struct termios t_old, t_new;

    if (!buf)
    {
        fprintf(stderr, "Out of memory.\n");
        return(NULL);
    }

    fprintf(stdout, "%s", prompt);
    fflush(stdout);

    /* don't echo the keystrokes to the screen */
    tcgetattr(fn, &t_old);           /* get the current settings */
    t_new = t_old;                   /* back them up */
    t_new.c_lflag &= ~ECHO;          /* remove ECHO */
    tcsetattr(fn,TCSADRAIN, &t_new); /* apply new attributes */

    res = fgets(buf, 4096, stdin);
    if(!res)
    {
        fprintf(stderr, "Error in input.\n");
        return(NULL);
    }
    n = strlen(res);
    while(buf[n-1] != '\n')
    {
        buf = (char *)realloc(buf, n + 4096);
        if(!buf)
        {
            fprintf(stderr,"Out of memory.\n");
            return(NULL);
        }
        res = fgets(buf+n, 4096, stdin);
        if(!res)
        {
            fprintf(stderr, "Error in input.\n");
            return(NULL);
        }
        n += strlen(res);
    }
    buf[n-1] = 0;
    tcsetattr(fn, TCSADRAIN, &t_old); /* restore ECHO */
    fprintf(stdout,"\n");
    return buf;
}

