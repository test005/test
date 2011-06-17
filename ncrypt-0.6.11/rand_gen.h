/*
 * header for rand_gen.h
 */

#define R_BIT          0 /* 0-1 */
#define R_BYTE         1 /* 0-255 */
#define R_SIGNEDWORD   2 /* 0-32768 */
#define R_UNSIGNEDWORD 3 /* 0-65535 */
#define R_SIGNEDLONG   4 /* 0-2147483647 */
#define R_UNSIGNEDLONG 5 /* 0-4294967295 */

int seed_rand_num (void);
unsigned long get_rand_num (int i);
void extend_mat (char *orig, unsigned char *material, int len);
void gen_rand_mat (unsigned char *material, int len);	
