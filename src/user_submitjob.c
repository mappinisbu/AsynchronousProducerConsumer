#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <openssl/md5.h>
#include <signal.h>

#include "sys_submitjob.h"

#define MAX_PAYLOAD 1024 /* maximum payload size*/
#define MAX_JOB_SIZE 15

#define SIG_TEST 44

struct sockaddr_nl src_addr, dest_addr;
int sock_fd;
int jobCount = 0;
struct msghdr msg;
struct nlmsghdr *nlmsg;
struct iovec iov;
struct iovec riov;
struct nlmsghdr *nlh;
struct msghdr msgh;
//struct msghdr* messages[MAX_JOB_SIZE]; // store structs to recieve messages before program ends
//struct nlmsghdr nlmessages[MAX_JOB_SIZE];
struct job* jobs[MAX_JOB_SIZE];

/*
Encrypt/Decrypt: 1
Compress: 2
Checksum: 3
concat files: 4
Remove job: 5
Change priority: 6
Count jobs: 7
List jobs: 8

*/

void receiveData(int n, siginfo_t *info, void *unused) {
	
	int ret = 0, ujid_len = 0, rbuf_len = 0i, rc = 0;
	char *msg;
	char *result = malloc(sizeof(char*));
	char *user_job_id;
	
	nlh = NULL;
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;

        riov.iov_base = (void *)nlh;
        riov.iov_len = nlh->nlmsg_len;
        msgh.msg_name = (void *)&dest_addr;
        msgh.msg_namelen = sizeof(dest_addr);
        msgh.msg_iov = &riov;
        msgh.msg_iovlen = 1;


   	// printf("return value from a job %i\n", info->si_int);
	rc = recvmsg(sock_fd, &msgh, 0);
	
	msg = NLMSG_DATA(nlh);
	//extract ret value
	memcpy(result, msg, 4);
	ret = *result-'0';
	memcpy(result, msg+4, 4);
	ujid_len = *result-'0';

	//if ret value is success - retrieve user job id
	user_job_id = (char*)malloc(ujid_len+1);
	memcpy(user_job_id, msg+8, ujid_len);
	*(user_job_id + ujid_len) = '\0';

	if(!ret)
	{	
		memcpy(result, msg+8+ujid_len, 4);
		rbuf_len = *result-'0';

		if(rbuf_len)
		{
			char *rbuf = malloc(rbuf_len+1);
			memcpy(rbuf, msg+12+ujid_len, rbuf_len);
			*(rbuf + rbuf_len) = '\0';
			printf("Success - user job : %s \t return value : %d \t return buffer : %s\n", user_job_id, ret, rbuf);
			free(rbuf);
		}
		else 
			printf("Success - user job : %s \t return value : %d\n", user_job_id, ret);
	}
	else
	{
		printf("Error - user job : %s \t return value : %d\n", user_job_id, ret);
        printf("Error is: %s\n", strerror(ret * -1));
	}
	//print ujob id scan struct job - print job code and print result if any
	//dec jobCount
	jobCount--;
    free(user_job_id);
    free(result);
    return;

}



int initializeNetLink()
{
    
    int rc = 0;
     //create socket
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
       
     if (sock_fd < 0)
    {
        rc = sock_fd;
        perror("error ");
        goto out;
    }

    //setting source address
    memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid(); /* self pid */

    //bind socket to source
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    //set destination
    memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; /* For Linux Kernel */
        dest_addr.nl_groups = 0; /* unicast */

 out:
     return rc;
}

void sigInit()
{
    struct sigaction sig;
    sig.sa_sigaction = receiveData;
    sig.sa_flags = SA_SIGINFO;
    sigaction(SIG_TEST, &sig, NULL);

}

int main(int argc, const char *argv[])
{
    int rc = 0,i = 0;
    char ch;
    int dontwait = MSG_DONTWAIT;
    struct job_maintain_count* myjobCount ;
    struct job_maintain_list* myjobList; 
    sigInit();

    rc = initializeNetLink();
    if(rc != 0)
    {
        printf(" Problem with opening netlink connection\n");
        return -1;
    }

    printf("Welcome to submit job tool.\n Press 'y' to continue \n Press 'n' to exit\n ");
    scanf(" %c", &ch);

    while(ch == 'y')
    {
        int option;
        dontwait = MSG_DONTWAIT;
        printf(" Select your job from the list\n1 xcrypt \n2 Compress \n3 Checksum \n4 Concat Files \n5 Remove Job \n6 Change priority\n7 Count Jobs \n8 List jobs \n9 Exit\n");

        scanf(" %d", &option);
        
        printf("You selected option: %d\n", option);

	if(option == 9)
		break;

        struct job *myjob = (struct job*)malloc(sizeof(struct job));
        char desc[256];
        memset(desc, 0, 256);
        printf("\nEnter a string that servers as your job description: ");
        scanf("%s", desc);

        int len = strlen(desc) + 1;
        myjob->user_job_id = (char*)malloc(len);
        memset(myjob->user_job_id, 0, len);
        strcpy(myjob->user_job_id, desc);

        printf("\nEnter a priority between 1 and 8 : ");
        scanf("%d", &(myjob->priority));
        printf("\nType 1 if you require atomicity, 0 if you dont: ");
        scanf("%d", &(myjob->is_atomic));
        

        if(option == 1){
                      struct job_xcrypt* myxcryptjob = (struct job_xcrypt*)malloc(sizeof(struct job_xcrypt));
                      char inputFile[256];
                      memset(inputFile, 0, 256);
                      char outputFile[256];
                      memset(outputFile, 0, 256);
                      char pass[256];
                      memset(pass, 0, 256);
 
                      printf("\nEnter 1 if you want to encrypt or 0 if you want to decrypt");
                      scanf("%d", &(myxcryptjob->flag));

                      printf("\nEnter the input file name: ");
                      scanf("%s", inputFile);
                      int len = strlen(inputFile) + 1;
                      myxcryptjob->ipFile = (char*)malloc(len);
                      memset(myxcryptjob->ipFile, 0, len);
                      strcpy(myxcryptjob->ipFile, inputFile);

                      //printf(" input file: %s", myxcryptjob->ipFile);

                      printf("\nEnter the output file name: ");
                      scanf("%s", outputFile);
                      len = strlen(outputFile) + 1;
                      myxcryptjob->opFile = (char*)malloc(len);
                      memset(myxcryptjob->opFile, 0, len);
                      strcpy(myxcryptjob->opFile, outputFile);

                      printf("\nEnter the passphrase: ");
                      scanf("%s", pass);
                      // take md5 sum of the key
                      //printf("%d", passlength);
                      unsigned char* passwordDigest = (unsigned char*)malloc(17);
                      memset(passwordDigest, 0, 17);
                      MD5((const unsigned char *)pass,  strlen(pass), passwordDigest);
                      passwordDigest[16] = '\0';
                      myxcryptjob->key = (char*)malloc(17);
                      memset(myxcryptjob->key, 0, 17);
                      strcpy(myxcryptjob->key, (char*)passwordDigest);
                      myxcryptjob->keylen = 17;
                      
                      //myxcryptjob->cipher_name = "AES";

                      myjob->job_code = 1;
                      myjob->operation = myxcryptjob;

       }
       else if(option == 2)
       {
                      struct job_xcompress *mycompress = (struct job_xcompress*)malloc(sizeof(struct job_xcompress));
                      printf("\nEnter 1 if you want to compress or 0 if you want to decompress");
                      scanf("%d", &(mycompress->flag));
                      
                      char inputFile[256];
                      memset(inputFile, 0, 256);
                      char outputFile[256];
                      memset(outputFile, 0, 256);

                      printf("\nEnter the input file name: ");
                      scanf("%s", inputFile);
                      int len = strlen(inputFile) + 1;
                      mycompress->ipFile = (char*)malloc(len);
                      memset(mycompress->ipFile, 0, len);
                      strcpy(mycompress->ipFile, inputFile);

                      //printf(" input file: %s", myxcryptjob->ipFile);

                      printf("\nEnter the output file name: ");
                      scanf("%s", outputFile);
                      len = strlen(outputFile) + 1;
                      mycompress->opFile = (char*)malloc(len);
                      memset(mycompress->opFile, 0, len);
                      strcpy(mycompress->opFile, outputFile);

                      mycompress->compression_algo="lzo";
                      myjob->job_code = 2;
                      myjob->operation = mycompress;

                      
       }
       else if(option == 3)
       {
                      struct job_checksum *mychecksum = (struct job_checksum*)malloc(sizeof(struct job_checksum));
                      char inputFile[256];
                      memset(inputFile, 0, 256);
                      char hashalgo[256];
                      memset(hashalgo, 0, 256);


                      printf("\nEnter the input file name: ");
                      scanf("%s", inputFile);
                      int len = strlen(inputFile) + 1;
                      mychecksum->ipFile = (char*)malloc(len);
                      memset(mychecksum->ipFile, 0, len);
                      strcpy(mychecksum->ipFile, inputFile);

                      mychecksum->hash_algo = "md5";
                      
                      mychecksum->algo_len = 16;
                      myjob->job_code = 3;
                      myjob->operation = mychecksum;
                              
 
       }
       else if(option == 4){
                      struct job_concatfiles *myconcat = (struct job_concatfiles*)malloc(sizeof(struct job_concatfiles));

                      printf("\n Enter the number of files: ");
                      scanf("%d", &(myconcat->file_count)); 

                      char **file = (char**) calloc(myconcat->file_count, sizeof(char*));

                      int i = 0;
                      char inputFile[256];
                      memset(inputFile, 0, 256);

                      for(i = 0; i < myconcat->file_count; i++)
                      {
                          memset(inputFile, 0, 256);
                          printf("\nEnter the %d file: ", i);
                          scanf("%s", inputFile);

                          int len = strlen(inputFile) + 1;
                          file[i] = (char*)malloc(len);
                          memset(file[i], 0, len);
                          strcpy(file[i], inputFile);

    
                      }
                      myconcat->files = file;

                      char outputFile[256];
                      memset(outputFile, 0, 256);
              
                      printf("\nEnter the output file name: ");
                      scanf("%s", outputFile);
                      int len = strlen(outputFile) + 1;
                      myconcat->opFile = (char*)malloc(len);
                      memset(myconcat->opFile, 0, len);
                      strcpy(myconcat->opFile, outputFile);

                      /*char **file = (char *[]){"input/file1", "input/file2", "input/file3"};
                      struct job_concatfiles *myconcat = (struct job_concatfiles*)malloc(sizeof(struct job_concatfiles));
                      myconcat->file_count = 3;
                      myconcat->files = file;
                      myconcat->opFile = "some/output/file";*/
                      myjob->job_code = 4;
                      myjob->operation = myconcat;
            
        }
        else if(option == 5){

                      struct job_maintain_remove* myjobremove = (struct job_maintain_remove*)malloc(sizeof(struct job_maintain_remove));
                      char user_job_Id[256];
                      memset(user_job_Id, 0, 256);


                      printf("\nEnter the job id to be removed: ");
                      scanf("%s", user_job_Id);
                      int len = strlen(user_job_Id) + 1;
                      myjobremove->user_job_id = (char*)malloc(len);
                      memset(myjobremove->user_job_id, 0, len);
                      strcpy(myjobremove->user_job_id, user_job_Id);

                      myjob->job_code = 5;
                      myjob->operation = myjobremove;
                      dontwait = 0;
                    
        }
        else if(option == 6)
        {
                      struct job_maintain_chpriority* myjobchpriority = (struct job_maintain_chpriority*)malloc(sizeof(struct job_maintain_chpriority));
                      char user_job_Id[256];
                      memset(user_job_Id, 0, 256);


                      printf("\nEnter the job id whose priority is to be changed: ");
                      scanf("%s", user_job_Id);
                      int len = strlen(user_job_Id) + 1;
                      myjobchpriority->user_job_id = (char*)malloc(len);
                      memset(myjobchpriority->user_job_id, 0, len);
                      strcpy(myjobchpriority->user_job_id, user_job_Id);

                      myjob->job_code = 6;
                      myjob->operation = myjobchpriority;
                      dontwait = 0;


        }
        else if(option == 7)
        {
                        int jobc = 0;
                      myjobCount = (struct job_maintain_count*)malloc(sizeof(struct job_maintain_count));
                     

                      myjobCount->job_count = &jobc;
                      myjob->job_code = 7;
                      myjob->operation = myjobCount;
                      dontwait = 0;

        }
        else if(option == 8)
        {
                     myjobList = (struct job_maintain_list*)malloc(sizeof(struct job_maintain_list));
                     int buffLen = 0;
                     printf("\nEnter the buffer length: ");
                     scanf("%d", &buffLen);

                     myjobList->buf = (char*) malloc(buffLen);
                     memset( myjobList->buf, 0, buffLen);
                     
                     myjobList->buflen = buffLen;
                     myjob->job_code = 8;
                     myjob->operation = myjobList;
                     dontwait = 0;
        }



	nlmsg = NULL;	
        nlmsg = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlmsg, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlmsg->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlmsg->nlmsg_pid = getpid();
        nlmsg->nlmsg_flags = 0;

        memcpy(NLMSG_DATA(nlmsg), (void*)myjob, sizeof(struct job));

        iov.iov_base = (void *)nlmsg;
        iov.iov_len = nlmsg->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        printf("Sending message to kernel\n");
        rc = sendmsg(sock_fd, &msg, 0);
		
    	if(rc < 0)
	   {
		perror("Error in sending the message ");
		free(myjob);
		continue;
	    }
	
	
		//printf("sent message\n");
        	jobs[jobCount] = myjob;
        	jobCount++;
	


        //printf("Sent message\n");

        // put the msg and nlmsg in array?


       if(dontwait == 0)
       {
            receiveData(0,NULL, NULL);
             //printf(" in dontwait\n");
               if(option == 7){
                   //printf("The number of jobs in the queue are %p\n",(myjobCount->job_count));
                   printf("The number of jobs in the queue are %d\n",*myjobCount->job_count);
                }
                if(option ==8)
                    printf("The list of jobs is \n %s\n",myjobList->buf);
               //printf("Received message payload: %s\n", (char*)NLMSG_DATA(nlmsg));

        }
        printf(" Do you want to submit another job?\n");
        scanf(" %c", &ch);
    }

	 if(jobCount > 0)
	 {
		 while(jobCount)
			receiveData(0,NULL, NULL);
	 }
	for(i = 0; i <  MAX_JOB_SIZE ; i++)
	{
		if((struct job*)(jobs[i]) != NULL)
			free(jobs[i]);
	}
	
     close(sock_fd);
     return rc;
}
