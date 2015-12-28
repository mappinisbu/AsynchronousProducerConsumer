#ifndef SYSSUBMITJOB_H_  /*Guard*/
#define SYSSUBMITJOB_H_

#define NETLINK_USER 25
#define MAX_JOB_LIMIT 15

struct job
{
        int job_code;
        char *user_job_id;
        int priority;
        int is_atomic;
        int pid;
//    int error_flag;  /*TODO: check if used for call back */
//        char *return_value;
        void *operation;
};

struct job *globaljob;

struct job_xcrypt
{
        int flag;		/* 0 for encrypt and 1 for decrypt */
        char* ipFile;
        char* key;
        int keylen;
        char* opFile;
};

struct job_xcompress
{
        int flag;
        char* ipFile;
        char* compression_algo;
        char* opFile;
};

struct job_checksum
{
        char* ipFile;
        char* hash_algo;
  //      char* checksum;		/* output param where kernel writes to user buf*/
        int algo_len;
};

struct job_concatfiles
{
        int file_count;
        char** files; /* char array of files whose depth is file_count */
        char* opFile; /* write concatenation output to this file */
};

struct job_maintain_chpriority
{
        char* user_job_id;

};

struct job_maintain_remove
{
        char* user_job_id;

};

struct job_maintain_list
{
        char *buf;
        int buflen; // just like read operation, we will write what we can to buffer
};

struct job_maintain_count
{
        int *job_count;
};

struct job_result
{
	int return_value;
	char *user_job_id;
	char *return_buf;
};

#endif


