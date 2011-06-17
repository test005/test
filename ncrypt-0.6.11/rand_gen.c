/*
 * Generate random material - Simple Nomad <thegnome@nmrc.org>
 * Reworked for additional strength and entropy
 * - Todd MacDermid <tmacd@synacklabs.net>
 * Use #include "rand_gen.h" in your code.
 *
 * 26Apr2003 - Tweak for djgpp compat.
 *
 * 21Apr2003 - Revised to use ISAAC as a stronger PRNG, and to use
 *             processor timing as entropy source, a la chapter 10 of
 *             "Building Secure Software" by John Viega and Gary McGraw
 *             
 * 30Oct2002 - Initial revision. seedrandnum and getrandnum are basically
 *             stolen from libnet, Copyright (c) 1998,1999 Mike D. Schiffman.
 */

#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <sched.h>
#ifndef STANDARD
#include "standard.h"
#endif
#ifndef RAND
#include "rand.h"
#endif
#include "rand_gen.h"

randctx ctx;

/*
 * seeds the prng, returns -1 if it fails, 1 if successful
 * Entropy estimation: Viega and McGraw estimate that this method provides
 * between 1 and 3 bits of entropy per sched_yield(). This puts us somewhere
 * between 256 and 768 bits of entropy, which should be sufficient.
 */

int seed_rand_num(void)
{
  struct timeval seed;
  int i;

  for(i = 0; i < RANDSIZ; i++) {
    if(gettimeofday(&seed, NULL) == -1) return (-1);
    ctx.randrsl[i] ^= seed.tv_sec ^ seed.tv_usec;
#ifndef WIN32 /* djgpp doesn't support this */
    sched_yield();
#endif
  }
  randinit(&ctx, TRUE);
  return (1);
}

/*
 * returns a random number after being passed a value
 */
unsigned long get_rand_num(int i)
{
  unsigned long j;
  j = rand(&ctx);

  switch (i)
  {
    case R_BIT: return (j % 0x2);               /* 0-1 */
    case R_BYTE: return (j % 0xff);             /* 0-255 */
    case R_SIGNEDWORD: return (j % 0x7fff);     /* 0-32768 */
    case R_UNSIGNEDWORD: return (j % 0xffff);   /* 0-65535 */
    case R_SIGNEDLONG: return (j % 0x7fffffff); /* 0-2147483647 */
    case R_UNSIGNEDLONG: return (j);            /* 0-4294967295 */
  }
  return(0);
}

/*
 * Takes orig and filled material with origorigorig etc, len is length of
 * material variable.
 *
 * Call like this:
 *
 * char *text;
 * unsigned char somematerial[256];
 *
 * extend_mat(text,&somematerial[0],256);
 */
void extend_mat(char *orig, unsigned char *material, int len)
{
  int i,k,j=0;

  k = strlen(orig);
  for(i=0;i<len;i++)
  {
    material[i] = orig[j++];
    if(j == k) j=0;
  }
}
/*
 * writes random data to material, len is length of material, call
 * seed_rand_num before calling this routine
 *
 * Call like this:
 *
 * unsigned char randmaterial[1024];
 *
 * gen_rand_mat(&randmaterial[0],1024);
 */
void gen_rand_mat(unsigned char *material, int len)
{
  int i;

  for(i=0;i<len;i++) material[i] = get_rand_num(R_BYTE);
}
