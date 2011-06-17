#include "ncrypt.h"
#include "decrypt_file.h"

void decrypt_file(FILE* ifp, FILE* ofp, int algo)
{
    BYTE block[4 * 4];
    long int fsize = 0;
    int size = 0;

    size = fread(&fsize, sizeof(long int), 1, ifp);
    if (size <= 0)
    {
        fprintf(stderr,"*** Error reading data\n");
        exit(-1);
    }
    while (1)
    {
        guaranteed_memset(block, 0, 16);
        size = fread(block, 1, 16, ifp);
        if (size <= 0) break;
        switch(algo)
        {
          case RIJNDAEL: 
            blockDecryptR(&cipherInst, &keyInstR, block, 128, block);
            break;
          case SERPENT:
            blockDecryptS(&cipherInst, &keyInstS, block, 128, block);
            break;
          case TWOFISH:
            blockDecryptT(&cipherInstT, &keyInstT, block, 128, block);
            break;
        }
        /* on last block, eliminate the padding if it exists */
        if(fsize < 17) /* last block */
        {
            if (fwrite(block, (int)fsize, 1, ofp) != 1)
            {
                fprintf(stderr,"** ERROR writing data from last block\n");
                exit(-1);
            }
            break;
        }
        else /* otherwise, normal writing to decrypt file */
        {
            if (fwrite(block, 16, 1, ofp) != 1)
            {
                fprintf(stderr,"** ERROR writing data\n");
                exit(-1);
            }
        }
        fsize -= size;
    }
}

