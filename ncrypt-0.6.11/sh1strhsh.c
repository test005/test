#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha1.h"


char *hash_string_with_sha1(char *string_to_hash)
{
    SHA1_CTX sha;
    int i, j, index = 0;
    unsigned char *temp = (unsigned char *)malloc(3 * sizeof(unsigned char));
	  unsigned char *hashcode = (unsigned char *)malloc(21 * sizeof(unsigned char));
	  unsigned char *hashed_string = (unsigned char *)malloc(41 * sizeof(unsigned char));
	
	
	  temp[2] = '\0';
	  hashed_string[40] = '\0';
	  hashcode[40] = '\0';
	
    SHA1Init(&sha);
    SHA1Update(&sha, (unsigned char *)string_to_hash, strlen(string_to_hash));   
    SHA1Final(hashcode, &sha);
	
	  for (i = 0; i < 5; i++)                             
		    for (j = 0; j < 4; j++)
		    {
				    sprintf((char *)temp, "%02x", hashcode[i * 4 + j]);
					
					  hashed_string[index++] = temp[0];        
					  hashed_string[index++] = temp[1];
				}
	
	  free(temp);
	  free(hashcode);
	
	  return (char *)hashed_string;
}
