/*
 * wipe_file - Simple Nomad <thegnome@nmrc.org>
 *
 * 14Jul2003 - NTFS has issues with these file slack and verify routines
 *             so until they are fixed, WIN32 doesn't fully implement
 *             military wiping or wiping of file slack. Probably an issue
 *             djgpp.
 * 21Apr2003 - Added fsync after each write, and randomly shuffled the
 *             27 passes. Todd MacDermid <tmacd@synacklabs.net>
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "ncrypt.h"
#include "rand_gen.h" 
#include "wipe_file.h"

#ifdef WIN32
#define O_SYNC 010000
#endif

unsigned char raw_wipe[27][3] =
{{0x55,0x55,0x55}, {0xaa,0xaa,0xaa}, {0x92,0x49,0x24}, {0x49,0x24,0x92},
 {0x24,0x92,0x49}, {0x00,0x00,0x00}, {0x11,0x11,0x11}, {0x22,0x22,0x22},
 {0x33,0x33,0x33}, {0x44,0x44,0x44}, {0x55,0x55,0x55}, {0x66,0x66,0x66},
 {0x77,0x77,0x77}, {0x88,0x88,0x88}, {0x99,0x99,0x99}, {0xaa,0xaa,0xaa},
 {0xbb,0xbb,0xbb}, {0xcc,0xcc,0xcc}, {0xdd,0xdd,0xdd}, {0xee,0xee,0xee},
 {0xff,0xff,0xff}, {0x92,0x49,0x24}, {0x49,0x24,0x92}, {0x24,0x92,0x49},
 {0x6d,0xb6,0xdb}, {0xb6,0xdb,0x6d}, {0xdb,0x6d,0xb6}};

unsigned char raw_char[2][1] = {{0xf0},{0x0f}};

/*
 * wipe the file slack
 */
int wipe_slack(char *filename, int verbose, int wipe_mode)
{
	int fd;
	int deck[27];
	char *buf, *buf2;
	struct stat statbuf;
	ssize_t slack;
	int i,j,k,temp;

	if(stat(filename,&statbuf) == -1) return (FILE_NOT_FOUND);	
	slack = statbuf.st_blksize - (statbuf.st_size % statbuf.st_blksize);
	if (slack == statbuf.st_blksize)
	{
		if (verbose) fprintf(stderr,"No file slack found for file %s\n",filename);
		return(SUCCESS);
	}
	buf = malloc(statbuf.st_blksize);
	if((wipe_mode == WIPE_GUTMANN) || (wipe_mode == WIPE_BOTH))
	{
		if((fd=open(filename, O_WRONLY | O_SYNC)) < 0) 
		{
			fprintf(stderr, "Error accessing %s : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			return (FILE_NOT_WRITEABLE);
		}
		if (verbose) fprintf(stderr,"Wiping %s file slack [                                   ]\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b",filename);
		for(i=0;i<4;i++) /* four passes with random data */
		{
			if(verbose) fprintf(stderr,"*");
			gen_rand_mat(&buf[0],statbuf.st_blksize); 
			if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
			{
				fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return (FILE_ERR);
			}
			if(write(fd,(const void *)buf,slack) == -1)
			{
				fprintf(stderr,"Error overwriting %s file slack : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return(FILE_ERR);
			}
			fsync(fd);
		}
		/* random ordering of the 27 passes */
		for(i=0;i<27;i++) deck[i] = i;
		for(i=0;i<27;i++)
		{
			deck[i] = deck[get_rand_num(R_UNSIGNEDLONG) % 27];
			j = get_rand_num(R_UNSIGNEDLONG) % 27;
			temp = deck[i];
			deck[i] = deck[j];
			deck[j] = temp;
		}
		for(i=0;i<27;i++) /* 27 passes with data to thwart forensic recovery */
		{
			if (verbose) fprintf(stderr,"*");
			k = deck[i];
			extend_mat(raw_wipe[k],&buf[0],statbuf.st_blksize);
			if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
			{
				fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return(FILE_ERR);
			}
			if(write(fd,(const void *)buf,slack) == -1)
			{
				fprintf(stderr,"Error overwriting %s file slack : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return(FILE_ERR);
			}
			fsync(fd);
		}
		for(i=0;i<4;i++) /* four more passes with random data */
		{
			if(verbose) fprintf(stderr,"*");
			gen_rand_mat(&buf[0],statbuf.st_blksize);
			if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
			{
				fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return (FILE_ERR);
			}
			if(write(fd,(const void *)buf,slack) == -1)
			{
				fprintf(stderr,"Error overwriting %s file slack : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				return(FILE_ERR);
			}
			fsync(fd);
		}
		close(fd);
		if (verbose) fprintf(stderr,"] ");
	}
	if((wipe_mode == WIPE_MILITARY) || (wipe_mode == WIPE_BOTH))
	{
		if((wipe_mode == WIPE_BOTH) && (verbose)) fprintf(stderr,"\n");
		buf2 = malloc(statbuf.st_blksize);
		if((fd=open(filename, O_RDWR | O_SYNC)) < 0)
		{
			fprintf(stderr, "Error accessing %s : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return (FILE_NOT_WRITEABLE);
		}
		if (verbose) fprintf(stderr,"Wiping %s file slack [   ]\b\b\b\b",filename);
		for(i=0;i<2;i++)
		{
			if(verbose) fprintf(stderr,"*");
			extend_mat(raw_char[i],&buf[0],statbuf.st_blksize);
			if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
			{
				fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				free(buf2);
				return (FILE_ERR);
			}
			if(write(fd,(const void *)buf,slack) == -1)
			{
				fprintf(stderr,"Error overwriting %s file slack : %s\n",filename,strerror(errno));
				ftruncate(fd,statbuf.st_size);
				close(fd);
				free(buf);
				free(buf2);
				return(FILE_ERR);
			}
			fsync(fd);
		}
		if(verbose) fprintf(stderr,"*");
		gen_rand_mat(&buf[0],statbuf.st_blksize);
		if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
		{
			fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return (FILE_ERR);
		}
		if(write(fd,(const void *)buf,slack) == -1)
		{
			fprintf(stderr,"Error overwriting %s file slack : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return(FILE_ERR);
		}
		if(lseek(fd,statbuf.st_size,SEEK_SET) == -1)
		{
			fprintf(stderr,"Error seeking end of %s : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return (FILE_ERR);
		}
		if(read(fd,(void *)buf2,slack) == -1)
		{
			fprintf(stderr,"Error verifying overwrite of %s file slack : %s\n",filename,strerror(errno));
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return (FILE_ERR);
		}
		if(strncmp((const char *)buf,(const char *)buf2,slack)!=0)
		{
			fprintf(stderr,"\n\nWARNING: Verification failed during wipe of %s file slack\n",filename);
			ftruncate(fd,statbuf.st_size);
			close(fd);
			free(buf);
			free(buf2);
			return (FILE_ERR);
		}
		close(fd);
		if (verbose) fprintf(stderr,"] ");
		free(buf2);
	}
	free(buf);
	if (verbose) fprintf(stderr,"done\n");
	return(SUCCESS);
}


/*
 * securely erase a file, using Peter Gutmann's overwrite techniques,
 * or the DoD 5220.22-M standard for the military, or both.  
 */
int wipe_file(char *filename, int verbose, int wipe_mode)
{
	int fd;
	int deck[27];
	struct stat statbuf;
	unsigned char wipeMaterial[256];
	unsigned char verifyMaterial[256];
	int i,j,k,blocks,extra,temp,temp2,rc;

	if(seed_rand_num() == -1) return (SEED_ERR);
        if(verbose)
	{
		fprintf(stderr,"Wiping mode:\n");
		if ((wipe_mode == WIPE_GUTMANN) || (wipe_mode == WIPE_BOTH))
			fprintf(stderr,"  Gutmann (35 passes, anti-forensic)\n");
		if ((wipe_mode == WIPE_MILITARY) || (wipe_mode == WIPE_BOTH))
			fprintf(stderr,"  Military (3 passes, meets DoD 5220.22-M Chap. 8 standards)\n");
	}
#ifndef WIN32
	rc = wipe_slack(filename,verbose,wipe_mode);
	if(rc != SUCCESS) return rc;
#endif
	if(stat(filename,&statbuf) == -1)
	{
		return (FILE_NOT_FOUND);
	}
	i = (int)statbuf.st_size; 

	/* determine number of 256 byte blocks, plus the extra (if any) */
        extra = i % 256;
	blocks = (i - extra) / 256;

	if((wipe_mode == WIPE_GUTMANN) || (wipe_mode == WIPE_BOTH))
	{
		if((fd=open(filename, O_WRONLY | O_SYNC)) < 0)
		{
			fprintf(stderr, "Error accessing %s : %s\n",filename,strerror(errno));
			return (FILE_NOT_WRITEABLE);
		}
		if (verbose) fprintf(stderr,"Wiping %s from drive [                                   ]\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b",filename);
		/* 4 passes with each pass wiping with random data */
		for(i=0;i<4;i++)
		{
			if (verbose) fprintf(stderr,"*");
			if(lseek(fd,0,SEEK_SET)!=0)
			{
				fprintf(stderr,"Error seeking start of %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			/* wipe with random data */
			for(j=0;j<blocks;j++)
			{
				gen_rand_mat(&wipeMaterial[0],256);
				if(write(fd,wipeMaterial,256)!=256)
				{
					fprintf(stderr,"Error wiping %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			if(extra)
			{
				gen_rand_mat(&wipeMaterial[0],extra);
				if(write(fd,wipeMaterial,extra)!=extra)
				{
					fprintf(stderr,"Error wiping %s remaining data : %s\n",filename,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			fsync(fd);
		}
		/* set and shuffle the deck */
		for(i=0;i<27;i++) deck[i] = i;
		for(i=0;i<27;i++)
		{
			deck[i] = deck[get_rand_num(R_UNSIGNEDLONG) % 27];
			j = get_rand_num(R_UNSIGNEDLONG) % 27;
			temp = deck[i];
			deck[i] = deck[j];
			deck[j] = temp;
		}
		/* 27 passes with data to thwart forensic recovery */
		for(i=0;i<27;i++)
		{
			if (verbose) fprintf(stderr,"*");
			k = deck[i];
			if(lseek(fd,0,SEEK_SET)!=0)
			{
				fprintf(stderr,"Error seeking start of %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			extend_mat(raw_wipe[k],&wipeMaterial[0],256);
			for(j=0;j<blocks;j++)
				if(write(fd,wipeMaterial,256)!=256)
				{
					fprintf(stderr,"Error wiping %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			if(extra)
			{
				if(extra<3)
					for(j=0;j<extra;j++)
						wipeMaterial[j] = raw_wipe[k][j];
				else extend_mat(raw_wipe[i],&wipeMaterial[0],extra);
				if(write(fd,wipeMaterial,extra)!=extra)
				{
					fprintf(stderr,"Error wiping %s remaining data : %s\n",filename,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			fsync(fd);
		}
		/* 4 more passes with random data */
		for(i=0;i<4;i++)
		{
			if (verbose) fprintf(stderr,"*");
			if(lseek(fd,0,SEEK_SET)!=0)
			{
				fprintf(stderr,"Error seeking start of %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			/* wipe with random data */
			for(j=0;j<blocks;j++)
			{
				gen_rand_mat(&wipeMaterial[0],256);
				if(write(fd,wipeMaterial,256)!=256)
				{
					fprintf(stderr,"Error wiping %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			if(extra)
			{
				gen_rand_mat(&wipeMaterial[0],extra);
				if(write(fd,wipeMaterial,extra)!=extra)
				{
					fprintf(stderr,"Error wiping %s remaining data : %s\n",filename,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			fsync(fd);
		}
		close(fd);
		if (verbose) fprintf(stderr,"] ");
	}
	if ((wipe_mode == WIPE_MILITARY) || (wipe_mode == WIPE_BOTH))
	{
		if((wipe_mode == WIPE_BOTH) && (verbose)) fprintf(stderr,"\n");
		if((fd=open(filename, O_RDWR | O_SYNC)) < 0)
		{
			fprintf(stderr, "Error accessing %s : %s\n",filename,strerror(errno));
			return (FILE_NOT_WRITEABLE);
		}
		if (verbose) fprintf(stderr,"Wiping %s from drive [   ]\b\b\b\b",filename);
		for(i=0;i<2;i++)
		{
			if (verbose) fprintf(stderr,"*");
			if(lseek(fd,0,SEEK_SET)!=0)
			{
				fprintf(stderr,"Error seeking start of %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			extend_mat(raw_char[i],&wipeMaterial[0],256);
			for(j=0;j<blocks;j++)
			{
				if(write(fd,wipeMaterial,256)!=256)
				{
					fprintf(stderr,"Error wiping %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			if(extra)
			{
				if(write(fd,wipeMaterial,extra)!=extra)
				{
					fprintf(stderr,"Error wiping %s remaining data : %s\n",filename,strerror(errno));
					close(fd);
					return(FILE_ERR);
				}
			}
			fsync(fd);
		}
		/* wipe with random data */
		if (verbose) fprintf(stderr,"*");
		if(lseek(fd,0,SEEK_SET)!=0)
		{
			fprintf(stderr,"Error seeking start of %s : %s\n",filename,strerror(errno));
			close(fd);
			return(FILE_ERR);
		}
		for(j=0;j<blocks;j++)
		{
			gen_rand_mat(&wipeMaterial[0],256);
			if(write(fd,wipeMaterial,256)!=256)
			{
				if(extra) blocks += extra;
				fprintf(stderr,"Error wiping %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
#ifndef WIN32
			temp2=(lseek(fd,0,SEEK_CUR)-256);
			if(lseek(fd,temp2,SEEK_SET)!=temp2)
			{
				fprintf(stderr,"Error seeking in  %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			if(read(fd,verifyMaterial,256)!=256)
			{
				if(extra) blocks += extra;
				fprintf(stderr,"Error verifying %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			if(strncmp((const char *)wipeMaterial,(const char *)verifyMaterial,256)!=0)
			{
				fprintf(stderr,"\n\nWARNING: Verification failed during wipe of %s at block %d of %d\n",filename,j,blocks);
				close(fd);
				return(FILE_ERR);
			}
#endif
		}
		if(extra)
		{
			gen_rand_mat(&wipeMaterial[0],extra);
			if(write(fd,wipeMaterial,extra)!=extra)
			{
				fprintf(stderr,"Error wiping %s remaining data : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
#ifndef WIN32
			temp2=(lseek(fd,0,SEEK_CUR)-extra); 
			if(lseek(fd,temp2,SEEK_SET)!=temp2)
			{
				fprintf(stderr,"Error seeking in  %s : %s\n",filename,strerror(errno));
				close(fd);
				return(FILE_ERR);
			} 
			if(read(fd,verifyMaterial,extra)!=extra)
			{
				fprintf(stderr,"Error verifying %s block %d of %d : %s\n",filename,j,blocks,strerror(errno));
				close(fd);
				return(FILE_ERR);
			}
			if(strncmp((const char *)wipeMaterial,(const char *)verifyMaterial,extra))
			{
				fprintf(stderr,"\n\nWARNING: Verification failed during wipe of %s at block %d of %d\n",filename,j,blocks);
				close(fd);
				return(FILE_ERR);
			}
#endif
		}
		fsync(fd);
		close(fd);
		if (verbose) fprintf(stderr,"] ");
	}
	remove(filename);
	if (verbose) fprintf(stderr,"done\n");
	return(SUCCESS); 
}
