#include "ncrypt.h"
#include "encrypt_file.h"

void encrypt_file(FILE* ifp, long int fsize, FILE* ofp, int algo)
{
    BYTE block[4 * 4];
    int size = 0;

    /* we are writing the filesize into the very beginning of the
       encrypted file, so we can handle the decryption later on */
    if (fwrite(&fsize, sizeof(long int), 1, ofp) != 1)
    {
        fprintf(stderr,"** ERROR writing data\n");
        exit(-1);
    }

    while (1)
    {
        guaranteed_memset(block, 0, 16);
        size = fread(block, 1, 16, ifp);
        if (size <= 0)
        {
            fprintf(stderr,"** ERROR reading data\n");
            exit(-1);
        }
        switch(algo)
        {
          case RIJNDAEL:
            blockEncryptR(&cipherInst, &keyInstR, block, 128, block);
            break;
          case SERPENT:
            blockEncryptS(&cipherInst, &keyInstS, block, 128, block);
            break;
          case TWOFISH:
            blockEncryptT(&cipherInstT, &keyInstT, block, 128, block);
            break;
        }
        /* Note that on the last block, we are padding to 16 bytes,
           this is done to ensure complete decryption later on since the
           encryption and decryption is dependent on block sizes of
           16 bytes. Without padding, decryption would fail on the last
           block. */
        if (fwrite(block, 16, 1, ofp) != 1)
        {
            fprintf(stderr,"** ERROR writing data\n");
            exit(-1);
        }
        if(fsize<17) break;
        fsize -= size;
    }
}

