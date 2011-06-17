#ifndef _ncrypt_h_
#define _ncrypt_h_
/*  ncrypt.h  - adapted from several aes.h files for the algo's */
/*  $Id: ncrypt.h,v 1.4 2004/08/25 20:32:55 s-nomad Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rijndael-alg-fst.h"
#include "platform.h"

#define RIJNDAEL        1
#define SERPENT         2
#define TWOFISH         3
#define DIR_ENCRYPT     0    /*  Are we encrypting?  */
#define DIR_DECRYPT     1    /*  Are we decrypting?  */
#define WIPEONLY        2    /*  Are we only wiping a file?  */
#define MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */
#define TRUE            1
#define FALSE           0
#define BITSPERBLOCK  128    /* Default number of bits in a cipher block */
#define WIPE_GUTMANN	1
#define WIPE_MILITARY	2
#define WIPE_BOTH	3

#define BAD_KEY_DIR         -1  /* Key direction invalid, eg unknown value */
#define BAD_KEY_MAT         -2  /* Key material not of correct length */
#define BAD_KEY_INSTANCE    -3  /* Key passed is not valid  */
#define BAD_CIPHER_MODE     -4  /* Params struct passed to cipherInit invalid */
#define BAD_CIPHER_STATE    -5  /* Cipher in wrong state, eg not initialized */
#define BAD_BLOCK_LENGTH    -6 
#define BAD_INPUT_LEN       -6  /* twofish */
#define BAD_PARAMS          -7  /* twofish */
#define BAD_CIPHER_INSTANCE -7 
#define BAD_IV_MAT          -8  /* invalid IV text */
#define BAD_ENDIAN          -9  /* incorrect endianness define */
#define BAD_ALIGN32        -10  /* incorrect 32-bit alignment */

#define BLOCK_SIZE    128  /* number of bits per block */
#define MAX_KEY_SIZE   64  /* # of ASCII char's needed to represent a key */
#define MAX_IV_SIZE    32  /* # of ASCII char's needed to represent an IV  */
#define MAX_IV_SIZE_T  16  /* # of ASCII char's needed to represent an IV 
                              in Twofish */
#define MAX_ROUNDS     16  /* max # rounds (for allocating subkey array) */
#define ROUNDS_128     16  /* default number of rounds for 128-bit keys*/
#define ROUNDS_192     16  /* default number of rounds for 192-bit keys*/
#define ROUNDS_256     16  /* default number of rounds for 256-bit keys*/
#define MAX_KEY_BITS  256  /* max number of bits of key */
#define MIN_KEY_BITS  128  /* min number of bits of key (zero pad) */
#define VALID_SIG 0x48534946  /* initialization signature ('FISH') */
#define MCT_OUTER     400  /* MCT outer loop */
#define MCT_INNER   10000  /* MCT inner loop */
#define REENTRANT       1  /* nonzero forces reentrant code (slightly slower) */
#define INPUT_WHITEN    0       /* subkey array indices */
#define OUTPUT_WHITEN  ( INPUT_WHITEN + BLOCK_SIZE/32)
#define ROUND_SUBKEYS  (OUTPUT_WHITEN + BLOCK_SIZE/32) /* use 2 * (# rounds) */
#define TOTAL_SUBKEYS  (ROUND_SUBKEYS + 2*MAX_ROUNDS)
#define MAX_LINE      256

typedef unsigned char BYTE;
typedef unsigned long DWORD;            /* 32-bit unsigned quantity */
typedef DWORD fullSbox[4][256];

/* The structure for Twofish key information */
typedef struct 
{
  BYTE direction;               /* Key used for encrypting or decrypting? */
#if ALIGN32
  BYTE dummyAlign[3];           /* keep 32-bit alignment */
#endif
  int  keyLen;                  /* Length of the key */
  char keyMaterial[MAX_KEY_SIZE+4]; /* Raw key data in ASCII */

  /* Twofish-specific parameters: */
  DWORD keySig;                 /* set to VALID_SIG by makeKey() */
  int       numRounds;          /* number of rounds in cipher */
  DWORD key32[MAX_KEY_BITS/32]; /* actual key bits, in dwords */
  DWORD sboxKeys[MAX_KEY_BITS/64]; /* key bits used for S-boxes */
  DWORD subKeys[TOTAL_SUBKEYS]; /* round subkeys, input/output whitening bits */
#if REENTRANT
  fullSbox sBox8x32;            /* fully expanded S-box */
  #if defined(COMPILE_KEY) && defined(USE_ASM)
  #undef  VALID_SIG
  #define VALID_SIG 0x504D4F43  /* 'COMP':  C is compiled with -DCOMPILE_KEY */
  DWORD cSig1;                  /* set after first "compile" (zero at "init") */
  void *encryptFuncPtr;         /* ptr to asm encrypt function */
  void *decryptFuncPtr;         /* ptr to asm decrypt function */
  DWORD codeSize;               /* size of compiledCode */
  DWORD cSig2;                  /* set after first "compile" */
  BYTE  compiledCode[5000];     /* make room for the code itself */
  #endif
#endif
} keyInstanceT;

/*  The structure for Serpent key information */
typedef struct 
{
  BYTE  direction;              /*  Key used for encrypting or decrypting? */
  int   keyLen;                 /*  Length of the key  */
  char  keyMaterial[MAX_KEY_SIZE+1]; /*  Raw key data in ASCII, e.g.,
                                         what the user types or KAT values)*/
  /*  The following parameters are algorithm dependent, replace or
      add as necessary  */
  unsigned long key[8];         /* The key in binary */
  unsigned long subkeys[33][4]; /* Serpent subkeys */
} keyInstanceS;

/* The structure for Rijndael key information */

typedef struct 
{
  BYTE  direction;              /*  Key used for encrypting or decrypting? */
  int   keyLen;                 /*  Length of the key  */
  char  keyMaterial[MAX_KEY_SIZE+1]; /*  Raw key data in ASCII,
                                         e.g., user input or KAT values */
  /*  The following parameters are algorithm dependent, replace or
      add as necessary  */
  int   blockLen;               /* block length */
  word8 keySched[MAXROUNDS+1][4][4]; /* key schedule */
} keyInstanceR;

/*  The structure for cipher information */
typedef struct 
{
  BYTE  mode;                   /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
  char  IV[MAX_IV_SIZE];        /* A possible Initialization Vector for 
                                   ciphering */
  /*  Add any algorithm specific parameters needed here  */
  int   blockSize;              /* Sample: Handles non-128 bit block sizes
                                   (if available) */
} cipherInstance;

/* The structure for Twofish cipher information */
typedef struct 
{
  BYTE  mode;                   /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
#if ALIGN32
  BYTE  dummyAlign[3];          /* keep 32-bit alignment */
#endif
  BYTE  IV[MAX_IV_SIZE_T];      /* CFB1 iv bytes  (CBC uses iv32) */

  /* Twofish-specific parameters: */
  DWORD cipherSig;              /* set to VALID_SIG by cipherInit() */
  DWORD iv32[BLOCK_SIZE/32];    /* CBC IV bytes arranged as dwords */
} cipherInstanceT;

/* struct for args etc */
struct ncrypt
{
  int verbose ; /* Whether verbose was given.  */
  int algo ;
  int key ; /* whether password given on command line or not */
  int pfile ; /* whether password given in a text file */
  char **ifiles ;	/* multiple input files */
  unsigned ifiles_cnt ;	/* number of multiple input files */
} ;

/*  Function protoypes  */
char *read_pass(char *prompt);

int makeKeyT(keyInstanceT *key, BYTE direction, int keyLen, char *keyMaterial); 
int makeKeyS(keyInstanceS *key, BYTE direction, int keyLen, char *keyMaterial); 
int makeKeyR(keyInstanceR *key, BYTE direction, int keyLen, char *keyMaterial);

int cipherInitT(cipherInstanceT *cipher, BYTE mode, char *IV); 
int cipherInitS(cipherInstance *cipher, BYTE mode, char *IV); 
int cipherInitR(cipherInstance *cipher, BYTE mode, char *IV);

int blockEncryptT(cipherInstanceT *cipher, keyInstanceT *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);
int blockEncryptS(cipherInstance *cipher, keyInstanceS *key, BYTE *input, 
		 int inputLen, BYTE *outBuffer); 
int blockEncryptR(cipherInstance *cipher, keyInstanceR *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);

int blockDecryptT(cipherInstanceT *cipher, keyInstanceT *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);
int blockDecryptS(cipherInstance *cipher, keyInstanceS *key, BYTE *input,
		 int inputLen, BYTE *outBuffer); 
int blockDecryptR(cipherInstance *cipher, keyInstanceR *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);

int serpent_convert_from_string(int len, char *str, unsigned long *val);
void serpent_encrypt(unsigned long plaintext[4], 
		unsigned long ciphertext[4], 
		unsigned long subkeys[33][4]);
void serpent_decrypt(unsigned long ciphertext[4],
		unsigned long plaintext[4],
		unsigned long subkeys[33][4]);

int cipherUpdateRounds(cipherInstance *cipher, keyInstanceR *key, BYTE *input, 
                        int inputLen, BYTE *outBuffer, int Rounds);

int reKey(keyInstanceT *key); /* do key schedule using modified key.keyDwords */

/* API to check table usage, for use in ECB_TBL KAT */
#define TAB_DISABLE                     0
#define TAB_ENABLE                      1
#define TAB_RESET                       2
#define TAB_QUERY                       3
#define TAB_MIN_QUERY                  50
int TableOp(int op);

#define CONST                   /* helpful C++ syntax sugar, NOP for ANSI C */
#if BLOCK_SIZE == 128           /* optimize block copies */
#define         Copy1(d,s,N)    ((DWORD *)(d))[N] = ((DWORD *)(s))[N]
#define         BlockCopy(d,s)  { Copy1(d,s,0);Copy1(d,s,1);Copy1(d,s,2);Copy1(d,s,3); }
#else
#define         BlockCopy(d,s)  { memcpy(d,s,BLOCK_SIZE/8); }
#endif

extern keyInstanceT keyInstT;
extern keyInstanceS keyInstS;
extern keyInstanceR keyInstR;
extern cipherInstance cipherInst;
extern cipherInstanceT cipherInstT;
extern struct gengetopt_args_info ARGS;
extern const char* PROGNAME;
#endif

