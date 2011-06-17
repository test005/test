/* 
 * ncrypt.c - Simple Nomad <thegnome@nmrc.org>
 *          - Inertia <inertia@nmrc.org>
 *
 * NMRC file encryptor/decryptor - based off of AES code for Rijndael and
 * Serpent found on www.farm9.com. The original farm9 work done by Joh 
 * Johannsen <jojo@farm9.com>, which was based off of work done by Gary 
 * Rancier <mephis5@softhome.net>. The Twofish code was taken from Doug 
 * Whiting's C implementation from www.counterpane.com.
 * 
 * $Id: ncrypt.c,v 1.10 2004/08/25 20:20:36 s-nomad Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ncrypt.h"
#include "config.h"
#include "encrypt_file.h"
#include "decrypt_file.h"
#include "wipe_file.h"
#include "rand_gen.h"
#include "read_pass.h"
#include "sha1.h"
#include "mem.h"
#include "get_encryption_password.h"
#include "get_decryption_password.h"

#ifdef __FREEBSD__
#define LOCKING 0
#else
#define LOCKING 1
#endif

/**********
 * globals
 **********/
char* cli_key;
char* fpass;
keyInstanceT keyInstT;
keyInstanceS keyInstS;
keyInstanceR keyInstR;
cipherInstance cipherInst;
cipherInstanceT cipherInstT;
struct ncrypt NCRYPT;
const char* PROGNAME;

/**********
 * routines
 **********/

void initialize_options( void )
{
  NCRYPT.verbose = 0;
  NCRYPT.algo = 0;
  NCRYPT.key = 0;
  NCRYPT.pfile = 0;
}

void initialize_crypto(char* pass, int encrypt)
{
    BYTE keyMaterial[320];
    BYTE direction = (encrypt) ? DIR_ENCRYPT : DIR_DECRYPT;
    int r = 0;
    int i = 0;
    int len = 256; 

    if(NCRYPT.algo == TWOFISH) len = 128; 

    /* make plaintext password into a SHA1 hash */
    extend_mat(hash_string_with_sha1(pass), &keyMaterial[0], len);

    /* after hashing, erase the plaintext password instance from memory */
    guaranteed_memset(pass,0,strlen(pass));

    switch(NCRYPT.algo)
    {
      case RIJNDAEL:
        r = makeKeyR(&keyInstR, direction, len, keyMaterial);
        break;
      case SERPENT:
        r = makeKeyS(&keyInstS, direction, len, keyMaterial);
        break;
      case TWOFISH:
        r = makeKeyT(&keyInstT, direction, len, NULL);
        if (r == TRUE)
        {
            for(i=0; i<(len/32); i++) keyInstT.key32[i] = keyMaterial[i];
            reKey(&keyInstT);
        }
        break;
    }

    /* we've made our key from the hash, so remove the hash from memory */
    guaranteed_memset(keyMaterial,0,len);

    if (r != TRUE)
    {
        fprintf(stderr,"** ERROR: On makeKey: %d\n", r);
        exit(-1);
    }

    /* init the algo we are using */
    switch(NCRYPT.algo)
    {
      case RIJNDAEL:
        r = cipherInitR(&cipherInst,  MODE_CBC, NULL); break;
      case SERPENT:
        r = cipherInitS(&cipherInst,  MODE_ECB, NULL); break;
      case TWOFISH:
        r = cipherInitT(&cipherInstT, MODE_CBC, NULL); break;
    }
    if (r != TRUE)
    {
        fprintf(stderr,"** ERROR: On cipherInit: %d\n", r);
        exit(-1);
    }
}


#ifndef WIN32
void check_for_lockable_memory()
{
    int lock = 0;
    if (getuid() == 0)
    {
        lock = mlockall(MCL_CURRENT|MCL_FUTURE);
        if (lock == -1)
        {
            fprintf(stderr,"Running as root but unable to lock memory to prevent paging to swap\n");
            exit(-1);
        }
        lock = 1;
    }
    if (NCRYPT.verbose)
    {
	if (lock)
            fprintf(stderr,"NOTE: Running as root and memory is locked from paging to disk\n");
        else
            fprintf(stderr,"WARNING: Running unprivileged and memory is not locked from paging to disk\n");
    }
}
#endif


int wipe(int wipe_mode, char * ifile)
{
    int i = 0;
    
    if(ifile)
	    wipe_file(ifile,NCRYPT.verbose,wipe_mode);
    else for (i = 0 ; i < NCRYPT.ifiles_cnt ; i++)
	wipe_file(NCRYPT.ifiles[i],NCRYPT.verbose,wipe_mode);
    return 0;
}

int encrypt_it(FILE* ifp, FILE* ofp)
{
    struct stat statbuf;
    char* pass = NULL;

    if(NCRYPT.key)
    {
        initialize_crypto(cli_key,1);
        guaranteed_memset(cli_key,0,strlen(cli_key));
        free(cli_key);
    }
    else if(NCRYPT.pfile)
    {
        initialize_crypto(fpass,1);
        guaranteed_memset(fpass,0,strlen(fpass));
        free(fpass);
    }
    else
    {
        pass = get_encryption_password();
        initialize_crypto(pass,1);
        guaranteed_memset(pass,0,strlen(pass));
        free(pass);
    }
    fstat(fileno(ifp),&statbuf);
    encrypt_file(ifp,statbuf.st_size,ofp,NCRYPT.algo);
    return 0;
}



int decrypt_it(FILE* ifp, FILE* ofp)
{
    char* pass = NULL;
    if(NCRYPT.key)
    {
        initialize_crypto(cli_key,0);
        guaranteed_memset(cli_key,0,strlen(cli_key));
        free(cli_key);
    }
    else if(NCRYPT.pfile)
    {
        initialize_crypto(fpass,0);
        guaranteed_memset(fpass,0,strlen(fpass));
        free(fpass);
    }
    else
    {
        pass = get_decryption_password();
        initialize_crypto(pass,0);
        guaranteed_memset(pass,0,strlen(pass));
        free(pass);
    }
    decrypt_file(ifp,ofp,NCRYPT.algo);
    return 0;
}



FILE* determine_input_file(char * ifile)
{
    FILE* ifp;
    ifp = fopen(ifile,"rb");
    if (ifp == NULL)
    {
      fprintf(stderr,"ERROR: cannot open file for reading: %s\n",ifile);
      exit(-1); 
    }
    return ifp;
}



FILE* determine_output_file(char * ofile)
{
    FILE* ofp;
    ofp = fopen(ofile,"wb");
    if (ofp == NULL)
    {
        fprintf(stderr,"ERROR: cannot open file for writing: %s\n",ofile);
        exit(-1); 
    }
    return ofp;
}

#ifndef HAVE_STRDUP
/* gengetopt_strdup(): automatically generated from strdup.c. */
/* strdup.c replacement of strdup, which is not standard */
static char *gengetopt_strdup (const char *s)
{
        char *result = (char*)malloc(strlen(s) + 1);
        if (result == (char*)0)
                return (char*)0;
        strcpy(result, s);
        return result;
}
#endif /* HAVE_STRDUP */

void usage(int exit_state)
{
    printf("USAGE:\n"
    "  ncrypt <options> [ops] <-i in_file> <-o out_file> <wipe-only files>\n"
    "  Options include the following:\n"
    "    -h  --help          This help cruft\n"
    "    -V  --version       Print version and exit\n"
    "    -v  --verbose       Verbose mode\n"
    "    -a  --aes           Use AES when encrypting/decrypting (same as rijndael)\n"
    "    -r  --rijndael      Use rijndael when encrypting/decrypting (default)\n"
    "    -s  --serpent       Use serpent when encrypting/decrypting\n"
    "    -t  --twofish       Use twofish when encrypting/decrypting\n"
    "    -z  --encrypt-wipe  Wipe input file after encrypting\n"
    "    -k  --key <pass>    Supply the password on the commandline (dangerous)\n"
    "    -f  --password-file <filename.txt>\n"
    "                        Supply the password in a file (also dangerous)\n"
    "  Ops include the following:\n"
    "    -e  --encrypt       Encryption mode\n"
    "    -d  --decrypt       Decryption mode\n"
    "    -g  --wipe-gutmann  Wipe using Gutmann mode\n"
    "    -m  --wipe-military Wipe using DoD 5220.22-M (military grade) mode\n"
    "  More info, including usage examples, in the man page\n\n");
    exit(exit_state);
}

int main(int argc, char** argv)
{
    FILE* ifp = NULL;
    FILE* ofp = NULL;
    FILE* pfp = NULL;
    char * ifile = NULL;
    char * ofile = NULL;
    char * pfile = NULL;
    char buf[MAX_LINE+1];
    int encrypt=0, decrypt=0, line=0;
    int wipe_gutmann=0, wipe_military=0, wipe_only=0;
    int rc = 0, wipe_mode = 0, wipe_on_encrypt=0;
    int c,i,algo=0,wiping=0;
    int option_index = 0;
    static struct option long_options[] = {
      { "help",       0, NULL, 'h' },
      { "version",    0, NULL, 'V' },
      { "input",      1, NULL, 'i' },
      { "output",     1, NULL, 'o' },
      { "key",        1, NULL, 'k' },
      { "password-file",      1, NULL, 'f' },
      { "wipe-gutmann",       0, NULL, 'g' },
      { "verbose",    0, NULL, 'v' },
      { "encrypt",    0, NULL, 'e' },
      { "decrypt",    0, NULL, 'd' },
      { "wipe-military",      0, NULL, 'm' },
      { "aes",        0, NULL, 'a' },
      { "rijndael",   0, NULL, 'r' },
      { "serpent",    0, NULL, 's' },
      { "twofish",    0, NULL, 't' },
      { "encrypt-wipe",       0, NULL, 'z' },
      { NULL, 0, NULL, 0 }
    };
    PROGNAME = argv[0];
    cli_key = NULL;

    initialize_options();
    optind = 1;

    while(1)
    {
      c = getopt_long(argc, argv, "hVi:o:k:f:gvedmarstz", long_options, &option_index);
      if(c == -1) break;
      switch(c)
      {
        case 'h':
          usage(EXIT_SUCCESS);
        case 'V':
          printf("%s %s\n", PACKAGE, VERSION);
          exit(EXIT_SUCCESS);
        case 'i':
          if(ifile)
          {
            fprintf(stderr,"%s: --input (-i) used more than once\n",PACKAGE);
            exit(EXIT_FAILURE);
          }
          ifile = strdup(optarg);
          break;
        case 'o':
          if(ofile)
          {
            fprintf(stderr,"%s: --output (-o) used more than once\n",PACKAGE);
            exit(EXIT_FAILURE);
          }
          ofile = strdup(optarg);
          break;
        case 'k':
          if(cli_key)
          {
            fprintf(stderr,"%s: --key (-k) used more than once\n", PACKAGE);
            exit(EXIT_FAILURE);
          }
          cli_key = strdup(optarg);
          NCRYPT.key = 1;
          break;
        case 'f':
          if(pfile)
          {
            fprintf(stderr,"%s: --password-file (-f) used more than once\n", PACKAGE);
            exit(EXIT_FAILURE);
          }
          pfile = strdup(optarg);
          pfp = fopen(pfile,"r");
          if(!pfp)
          {
            fprintf(stderr,"%s: unable to open file containing password\n", PACKAGE);
            exit(EXIT_FAILURE);
          }
          buf[MAX_LINE] = 0;
          while (!feof(pfp))
          {
            fgets(buf,MAX_LINE,pfp);
            line++;
            if(buf[0]=='#') continue;
            if(buf[0]!='#')
            {
              if(strlen(buf) < 1) continue;
              for(i=0;i<MAX_LINE;i++)
                if(buf[i]=='\n') buf[i] = 0;
              fpass = strdup(buf);
              break;
            }
          }
          fclose(pfp);
          if(!buf)
          {
            fprintf(stderr,"%s: unable to find a password in file %s\n", PACKAGE, pfile);
            exit(EXIT_FAILURE);
          }
          NCRYPT.pfile = 1;
          break;
        case 'g':
          wipe_gutmann = 1;
          wiping++;
          break;
        case 'v':
          NCRYPT.verbose = 1;
          break;
        case 'e':
          encrypt = 1;
          break;
        case 'd':
          decrypt = 1;
          break;
        case 'm':
          wipe_military = 1;
          wiping++;
          break;
        case 'a':
          algo++;
          NCRYPT.algo = RIJNDAEL;
          break;
        case 'r':
          NCRYPT.algo = RIJNDAEL;
          algo++;
          break;
        case 's':
          NCRYPT.algo = SERPENT;
          algo++;
          break;
        case 't':
          NCRYPT.algo = TWOFISH;
          algo++;
          break;
        case 'z':
          wipe_on_encrypt = 1;
          break;
        case 0:
        case '?':
          exit(EXIT_FAILURE);
        default:
          fprintf(stderr,"%s: option unknown: %c\n",PACKAGE,c);
          usage(EXIT_FAILURE);
      }
    }

    /* post arg processing, this is ugly, but at least it is all in one place */
    /* can't encrypt AND decrypt at the same time */
    if(encrypt && decrypt)
    {
      fprintf(stderr,"%s: You must choose either to encrypt or decrypt, not both\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    /* must pick something, if not encrypting or decrypting and haven't chosen
       a wiping method we assume nothing and error out accordingly */
    if(!encrypt && !decrypt && !wiping)
    {
      fprintf(stderr,"%s: You must encrypt, decrypt, or wipe\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    /* if decrypting we don't need to be wiping */
    if(decrypt && wiping)
    {
      fprintf(stderr,"%s: If decrypting, you shouldn't be choosing wiping options\n",PACKAGE);
      usage(EXIT_FAILURE);
    }    
    /* so if we aren't encrypting ot decrypting, we must be wiping */
    if(!encrypt && !decrypt && wiping) wipe_only = 1;
    /* however if someone used the -i or -o option, maybe they were trying
       to encrypt and left out the -e option, which could be bad since we
       could securely wipe something that wasn't intended to be wiped */
    if(wipe_only && ifile)
    {
      fprintf(stderr,"%s: If wiping only, do not use the -i option\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    if(wipe_only && ofile)
    {
      fprintf(stderr,"%s: If wiping only, do not use the -o option\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    /* if encrypting or decrypting, we need an input and output file */
    if(encrypt || decrypt)
    {
      if(!ifile)
      {
        fprintf (stderr, "%s: An input file is required for encryption or decryption\n", PACKAGE);
        usage(EXIT_FAILURE);
      }
      if(!ofile)
      {
        fprintf (stderr, "%s: An output file is required for encryption or decryption\n", PACKAGE);
        usage(EXIT_FAILURE);
      }
    }
    /* the algo should be chosen only once */
    if(algo > 1)
    {
      fprintf(stderr,"%s: You made algorithm choices more than once\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    /* can't do -k and -f together */
    if((NCRYPT.pfile) && (NCRYPT.key))
    {
      fprintf(stderr,"%s: You cannot use -k and -f together\n",PACKAGE);
      usage(EXIT_FAILURE);
    }
    /* if we reach here and we've processed all options, anything left on the
       commandline is copied into ifiles and we store the count */
    if(optind < argc)
    {
      int i = 0;
      NCRYPT.ifiles_cnt = argc - optind;
      NCRYPT.ifiles = (char **)(malloc ((NCRYPT.ifiles_cnt)*sizeof(char *)));
      while(optind < argc)
        NCRYPT.ifiles[i++] = strdup(argv[optind++]);
    }
    /* if no algo chosen, we default to rijndael */
    if (!NCRYPT.algo) NCRYPT.algo = RIJNDAEL;
    if (NCRYPT.verbose && ofile)
    {
      switch(NCRYPT.algo)
      {
        case RIJNDAEL: printf("NOTE: using aes (rijndael)\n"); break;
        case SERPENT: printf("NOTE: using serpent\n"); break;
        case TWOFISH: printf("NOTE: using twofish\n"); break;
      }
    }
#ifndef WIN32
    check_for_lockable_memory();
#endif
    /* if using files, verify we can actually use them and get the handles */
    if (ifile) ifp = determine_input_file(ifile);
    if (ofile) ofp = determine_output_file(ofile);
    
    /* if wiping, determine wiping mode */
    if (wipe_gutmann) wipe_mode = WIPE_GUTMANN;
    if (wipe_military) wipe_mode = WIPE_MILITARY;
    if ((wipe_gutmann) && (wipe_military)) wipe_mode = WIPE_BOTH;
    if (!wipe_mode) wipe_mode = WIPE_MILITARY; // z option with no mode chosen
    /* final end of post arg processing */

    /* finally doing something */
    if (wipe_only) return wipe(wipe_mode,NULL);

    if (encrypt) 
    {
	    rc = encrypt_it(ifp,ofp);
	    if (wipe_on_encrypt && (rc == 0)) rc = wipe(wipe_mode,ifile);
    }
    if (decrypt) rc = decrypt_it(ifp,ofp);

    fclose(ifp);
    fclose(ofp);
    return rc;
}
