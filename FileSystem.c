#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <openssl/md5.h>
#include <fcntl.h> 
#include <unistd.h> 
#include "uthash.h"
int less_than_1024;
int less_than_2048;
int less_than_4096;
int more_than_4096;


struct entry * hash_table = NULL;

struct fileStruct{
	int offset;
	char name[NAME_MAX];
};

struct entry{
	char md5Hash[33];
	struct fileStruct duplicatedFileArray[512];
	int count;
	UT_hash_handle hh_handle;  
}entry;



double calculate(int count, int total){
	if(count == 0) return 0;
	double res = (double)count*100/total;
	return res;
}

char * md5_hash(char * block, blksize_t size) {
	MD5_CTX ctx;    
	unsigned char digest[MD5_DIGEST_LENGTH];
	char * md5 = (char *)malloc(33);
	MD5_Init(&ctx);
	MD5_Update(&ctx, block, size);
	MD5_Final(digest, &ctx);
	int i;
	for(i = 0; i < 16; ++i) {
		sprintf(&md5[i * 2], "%02x", (unsigned int)digest[i]);
	}
	return md5;
}

void FoundPtr(struct entry * entry_ptr,char * md5,int block_size,int offset,char * file_name){
	struct entry * new_entry_ptr = malloc(sizeof(entry));
	strcpy(new_entry_ptr->md5Hash,entry_ptr->md5Hash);
	new_entry_ptr->count = entry_ptr->count;
	new_entry_ptr->count += 1;
	new_entry_ptr->duplicatedFileArray[new_entry_ptr->count - 1].offset = offset * block_size;
	strcpy(new_entry_ptr->duplicatedFileArray[new_entry_ptr->count -1].name,file_name);
	int i=0;
	for(i=0; i<new_entry_ptr->count-1; i++){
		new_entry_ptr->duplicatedFileArray[i].offset = entry_ptr->duplicatedFileArray[i].offset;
		strcpy(new_entry_ptr->duplicatedFileArray[i].name,entry_ptr->duplicatedFileArray[i].name);
	}
	HASH_DELETE(hh_handle, hash_table, entry_ptr);
	HASH_ADD(hh_handle,hash_table,md5Hash,strlen(new_entry_ptr->md5Hash),new_entry_ptr);
}
int duplicates = 0;
void NotFoundPtr(struct entry * entry_ptr,char * md5,int block_size,int offset,char * file_name){
	struct entry * new_entry_ptr = malloc(sizeof(entry));
	strcpy(new_entry_ptr->md5Hash,md5);
	new_entry_ptr->count = 1;
	new_entry_ptr->duplicatedFileArray[0].offset = offset * block_size;
	strcpy(new_entry_ptr->duplicatedFileArray[0].name,file_name);
	HASH_ADD(hh_handle,hash_table,md5Hash,strlen(md5),new_entry_ptr);
	duplicates+=1;
}

int wasted_memory = 0;
int total_num_blocks = 0;
int getFileBlocks(char* file_path, int block_size){
	FILE* f = fopen(file_path, "r");
	if(f == NULL){
		exit(1);
	}

	char* ptr = malloc(block_size);
	int offset = 0;
	while(1){
		size_t file_bytes_read = fread(ptr, 1, block_size, f);
		if(file_bytes_read == 0) break;
		if(file_bytes_read < block_size){
			int temp = block_size - file_bytes_read;
			wasted_memory += temp;
		}
		char * md5 = md5_hash(ptr,block_size);
		struct entry * entry_ptr = malloc(sizeof(entry));
	    HASH_FIND(hh_handle,hash_table,md5,strlen(md5),entry_ptr);
	    if(entry_ptr!=NULL){
	    	FoundPtr(entry_ptr,md5,block_size,offset,file_path);
	    }else{
	    	NotFoundPtr(entry_ptr,md5,block_size,offset,file_path);
	    }
	    offset++;
	}
	total_num_blocks+=offset;
	return 0;
}

void listdir(const char *name)
{
    DIR *dir;
    struct dirent *entry;
    if (!(dir = opendir(name))) return;
	
	while(1) {
		if(!(entry = readdir(dir))) return;
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
		char* path = malloc(512);
		strcpy(path, name);
		strcat(path, "/");
		strcat(path, entry->d_name);
		struct stat buf;
		if(stat(path, &buf) == 0){
			if(S_ISDIR(buf.st_mode)){
				listdir(path); 
			}
			if(S_ISREG(buf.st_mode)){
				getFileBlocks(path, buf.st_blksize);
				if(buf.st_size < 1024){
					less_than_1024++;
				}else if(buf.st_size < 2048){
					less_than_2048++;
				}else if(buf.st_size < 4096){
					less_than_4096++;
				}else{
					more_than_4096++;
				}  
			}				
        }
	}
    closedir(dir);
}

int total_amount_of_files(){
	return  less_than_1024 +  less_than_2048 +  less_than_4096 +  more_than_4096;
}

int main(int argc, const char *argv[]){
	if(argc != 2){
		puts("Enter folder path as argument");
		exit(1);
	}
	less_than_1024 = 0;
	less_than_2048 = 0;
	less_than_4096 = 0;
	more_than_4096 = 0;
    listdir(argv[1]);
	int total_amount = total_amount_of_files();
	printf("%i files %f %% less than 1024 byte\n",  less_than_1024, calculate( less_than_1024, total_amount));
	printf("%i files %f %% less than 2048 byte\n",  less_than_2048, calculate( less_than_2048, total_amount));
	printf("%i files %f %% less than 4096 byte\n",  less_than_4096, calculate( less_than_4096, total_amount));
	printf("%i files %f %% more than 4096 byte\n",  more_than_4096, calculate( more_than_4096, total_amount));
	int i;
	struct entry * curr;
    for(curr=hash_table; curr != NULL; curr=curr->hh_handle.next) {
    	if(curr->count>=2){
    		printf("%s\n", curr->md5Hash);

			for(i=0; i<=curr->count-1; i++){
				printf("%d    %s\n",curr->duplicatedFileArray[i].offset,curr->duplicatedFileArray[i].name);
			}    	
		}			
    }
    printf("Number of duplicates are %d which is %d %% of disk\n", duplicates, duplicates*100/total_num_blocks);
    printf("Wasted memory is: %d\n", wasted_memory);    
    return 0;
}
