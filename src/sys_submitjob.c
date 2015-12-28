#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/mm.h> // for verify_area: defined in uacces.h
#include <linux/highmem.h>
#include <linux/slab.h>// for kmalloc and kfree
#include <linux/fs.h> // for file api
#include <linux/types.h>// for u8
#include <linux/stat.h> // for checking dir or file
#include <linux/namei.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
// for crypto stuff
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/md5.h>
#include <crypto/hash.h>

// for kthreads
#include <linux/kernel.h>
#include <linux/kthread.h>

#include "sys_submitjob.h"
#include "process_job.h"
struct job *globaljob;
struct task_struct *producer_task;
struct task_struct *consumer_task;
//struct mutex qmutex;
//static int jobCount;

//asmlinkage extern long (*sysptr)(void *arg, int argLen);
static void submitjob_recv_msg(struct sk_buff *skb);

struct netlink_kernel_cfg cfg = {
                .groups = 1,
                .input = submitjob_recv_msg,
        };
 
struct sock *nl_sk = NULL;

/*void result_send_msg(int pid, struct job* kjob, int ret)
{
        struct nlmsghdr *nlh;
        struct sk_buff *skb_out;
        int msg_size;
        char *result = (char*)kmalloc(sizeof(char*), GFP_KERNEL);
        char *msg = "Finished processing request. Check return value.";

        result = (char*)kmalloc(sizeof(char*), GFP_KERNEL);
        if(IS_ERR(result))
        {
                printk(KERN_ERR "Failed to allocate memeory to result\n");
                goto out_exit;
        }

        *result = ret+'0';
        printk("return value address %p\n", kjob->return_value);
        printk("return char %s\n", result);

        ret = copy_to_user(kjob->return_value, result, sizeof(char*));
        if(IS_ERR(ERR_PTR(ret)))
        {
                printk(KERN_ERR "Failed to copy to user\n");
                goto out;
        }
        msg_size = strlen(msg);

        // printk("pid %d\n", pid);
        * consumer should free prod_job if not maintenace task? */
   /*     skb_out = nlmsg_new(msg_size, 0);
        if(!skb_out) {
                printk(KERN_ERR "Failed to allocate new skb\n");
                goto out;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0; * not in mcast group */
     /*   strncpy(nlmsg_data(nlh), msg, msg_size);
        printk("sent message \n");
        ret = nlmsg_unicast(nl_sk, skb_out, pid);
        if (ret < 0)
                printk(KERN_INFO "Error while sending back to user\n");
out:
        kfree(result);
out_exit:
        return;
}*/
/*void process_job(struct job *currProcJob){

        printk("CURRENT Job code is %d\n",currProcJob->job_code);
        return;
}*/

int func_consume(void *data)	// Should free kernel job
{
        struct list_head *pos, *q;
        struct qStruct *tmp;
	struct job* cjob;
        set_current_state(TASK_INTERRUPTIBLE);
        while (!kthread_should_stop())
        {
                //printk("i consume\n");
                mutex_lock(&qmutex);

                list_for_each_safe(pos, q, &(queuehead.job_list_member))                // Iterating through jobs in the queue
                {
                        tmp= list_entry(pos, struct qStruct, job_list_member);
			cjob = tmp->currentJob;
                        printk("In consumer job code is %d\n",cjob->job_code);
                        jobCount--;
                        printk("In consumer job count is %d\n",jobCount);
                        list_del(pos);
			mutex_unlock(&qmutex);						// Unlocking before processing
                        process_job(nl_sk, cjob);                                   	// Processig the current Job    
                        kfree(tmp);
			mutex_lock(&qmutex);
			
                }
                if(jobCount == 0){
                	if(mutex_is_locked(&qmutex))
                        	mutex_unlock(&qmutex);
                        //schedule();
                }
                if(mutex_is_locked(&qmutex))
                        mutex_unlock(&qmutex);
                printk("before schedule\n");
                schedule();

                set_current_state(TASK_INTERRUPTIBLE);
        }
        return 0;

}

int func_produce(void *data)
{
        struct job** cjob_ptr;
        struct job* cjob;
        struct qStruct  *curr_qNode;
        struct qStruct  *qtmp;
	int ret = 0,flag= 0;
        set_current_state(TASK_INTERRUPTIBLE);
        while (!kthread_should_stop())
        {
		flag = 0;
                mutex_lock(&qmutex);
		cjob_ptr = (struct job **)(data);
		cjob = *cjob_ptr;	
                if(jobCount > MAX_JOB_LIMIT)
                {
                    ret = -EAGAIN;
                    goto unlock;
                }

                curr_qNode = kmalloc(sizeof(struct qStruct),GFP_KERNEL);
		if(IS_ERR(curr_qNode)){
			ret = -ENOMEM;
			goto unlock;	
		}

		printk("after cuur qnode alloc\n");
                curr_qNode->currentJob = cjob;
		printk("after cjob and cujob alloc\n");
		/***************************** Check if user id already exists ********************************/
		list_for_each_entry(qtmp, &(queuehead.job_list_member), job_list_member){
			if(strcmp(cjob->user_job_id,qtmp->currentJob->user_job_id) == 0){
				printk("JOB ALREADY PRESENT\n");
				ret = -EINVAL;
				goto unlock;
			}	
		}		
		/**********************************************************************************************/	
                if(jobCount == 0){
                        list_add_tail(&(curr_qNode->job_list_member),&(queuehead.job_list_member));
                        jobCount++;

                }
                else{
			// DONOT INSERT DUPLICATE user_job_id to be done	
                        list_for_each_entry(qtmp, &(queuehead.job_list_member), job_list_member){       // inserting into the queue according to prioirty
                                printk("BUFFER %d\n", qtmp->currentJob->priority);
                                if(cjob->priority > qtmp->currentJob->priority){
                                        list_add(&(curr_qNode->job_list_member),&(qtmp->job_list_member));
                			jobCount++;
					flag = 1;
					printk("Breaking\n");
					break;
                                }
                        }
			if(flag == 0){
				list_add_tail(&(curr_qNode->job_list_member),&(queuehead.job_list_member));
				printk("Adding when jobCount is NOT ZERO\n");
				jobCount++;	
			}
                }
                //printk("In produce job Count is %d",jobCount);
                if(jobCount == 1){
                        mutex_unlock(&qmutex);
                        wake_up_process(consumer_task);                                         //Waking up the consumer thread 
			printk("After waking up the consumer\n");
                }

		unlock:
                if(mutex_is_locked(&qmutex))
                        mutex_unlock(&qmutex);
		if(ret < 0){
			struct job_result *rjob = (struct job_result*)kmalloc(sizeof(struct job_result), GFP_KERNEL);
			rjob->user_job_id = (char*)kmalloc(strlen(cjob->user_job_id)+1, GFP_KERNEL);
			memcpy(rjob->user_job_id, cjob->user_job_id, strlen(cjob->user_job_id));
			*(rjob->user_job_id + strlen(cjob->user_job_id) + 1) = '\0';
			rjob->return_value = ret;
			rjob->return_buf = NULL;
			result_send_msg(nl_sk, rjob, cjob->pid,0);
		}
		printk("before prod sched\n");
                schedule();
                set_current_state(TASK_INTERRUPTIBLE);
        }
        return 0;
}
long copyFromUserland(const struct job* userArgs,struct job* kernelArgs)
{
        int ret = 0;

        //if((copy_from_user(kernelArgs, userArgs, sizeof(struct job))) < 0)
/*      ret = copy_from_user(kernelArgs, userArgs, sizeof(struct job));
        //if(ret != 0)
        {
                printk("in copy kernel args \n");
                ret = -EFAULT;
                goto out;
        }*/

/*        printk("job id %d\n", kernelArgs->job_code);
//        printk("ujob addr %p\n", userArgs);
//        printk("ujob id addr %p\n", &userArgs->job_code);
	printk("user job id %s\n", kernelArgs->user_job_id);
	printk("user job id addr %p\n", kernelArgs->user_job_id);
        printk("size of struct job %d\n", sizeof(struct job));
        printk("copied size %d\n", ret);*/
        kernelArgs->user_job_id = kmalloc(strlen_user(userArgs->user_job_id), GFP_KERNEL);
        if(IS_ERR(kernelArgs->user_job_id))
        {
                ret = -ENOMEM;
                goto out;
        }

//      memset(kernelArgs->user_job_id, 0,strlen_user(userArgs->user_job_id));
        ret = copy_from_user(kernelArgs->user_job_id, userArgs->user_job_id, strlen_user(userArgs->user_job_id));
        if(ret != 0)
        {
                printk("in copy user_job_id\n");
                ret = -EFAULT;
                goto out;// free infile
        }


/*
    printk(" job code: %d\n", kernelArgs->job_code);
    printk(" job priority: %d\n", kernelArgs->priority);
    printk(" job atomicity: %d\n", kernelArgs->is_atomic);
    printk(" job error flag: %d\n", kernelArgs->error_flag);
    printk(" user job name: %s\n", kernelArgs->user_job_id);
*/

        if(kernelArgs->job_code == 1)
        {
                struct job_xcrypt *uXcrypt = (struct job_xcrypt*)userArgs->operation;
                // the operation must be encryption
                kernelArgs->operation = (struct job_xcrypt*)kmalloc(sizeof(struct job_xcrypt), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_xcrypt*)kernelArgs->operation, uXcrypt, sizeof(struct job_xcrypt));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_xcrypt*)(kernelArgs->operation))->ipFile = kmalloc(strlen_user(uXcrypt->ipFile), GFP_KERNEL);
                if(IS_ERR(((struct job_xcrypt*)(kernelArgs->operation))->ipFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcrypt*)(kernelArgs->operation))->ipFile, uXcrypt->ipFile, strlen_user(uXcrypt->ipFile));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

                ((struct job_xcrypt*)(kernelArgs->operation))->key = kmalloc(strlen_user(uXcrypt->key), GFP_KERNEL);
                if(IS_ERR(((struct job_xcrypt*)(kernelArgs->operation))->key))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcrypt*)(kernelArgs->operation))->key, uXcrypt->key, strlen_user(uXcrypt->key));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_xcrypt*)(kernelArgs->operation))->opFile = kmalloc(strlen_user(uXcrypt->opFile), GFP_KERNEL);
                if(IS_ERR(((struct job_xcrypt*)(kernelArgs->operation))->opFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcrypt*)(kernelArgs->operation))->opFile, uXcrypt->opFile, strlen_user(uXcrypt->opFile));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

/*    printk(" file to encrypt: %s\n", kernelencryptjob->ipFile);
    printk(" output file: %s\n", kernelencryptjob->opFile);
    printk(" cipher name: %s\n", kernelencryptjob->cipher_name);
    printk(" keylen : %d\n", kernelencryptjob->keylen);*/
        }
        else if(kernelArgs->job_code == 2)
        {
                struct job_xcompress *uXcompress = (struct job_xcompress*)userArgs->operation;
                kernelArgs->operation = (struct job_xcompress*)kmalloc(sizeof(struct job_xcompress), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_xcompress*)(kernelArgs->operation), uXcompress, sizeof(struct job_xcompress));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_xcompress*)(kernelArgs->operation))->ipFile = kmalloc(strlen_user(uXcompress->ipFile), GFP_KERNEL);
                if(IS_ERR(((struct job_xcompress*)(kernelArgs->operation))->ipFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcompress*)(kernelArgs->operation))->ipFile, uXcompress->ipFile, strlen_user(uXcompress->ipFile));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

                ((struct job_xcompress*)(kernelArgs->operation))->compression_algo = kmalloc(strlen_user(uXcompress->compression_algo), GFP_KERNEL);
                if(IS_ERR(((struct job_xcompress*)(kernelArgs->operation))->compression_algo))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcompress*)(kernelArgs->operation))->compression_algo, uXcompress->compression_algo, strlen_user(uXcompress->compression_algo));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

                ((struct job_xcompress*)(kernelArgs->operation))->opFile = kmalloc(strlen_user(uXcompress->opFile), GFP_KERNEL);
                if(IS_ERR(((struct job_xcompress*)(kernelArgs->operation))->opFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_xcompress*)(kernelArgs->operation))->opFile, uXcompress->opFile, strlen_user(uXcompress->opFile));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }
        }
        else if(kernelArgs->job_code == 3)
        {
                struct job_checksum *uChecksum = (struct job_checksum*)userArgs->operation;
                kernelArgs->operation = (struct job_checksum*)kmalloc(sizeof(struct job_checksum), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_checksum*)(kernelArgs->operation), uChecksum, sizeof(struct job_checksum));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_checksum*)(kernelArgs->operation))->ipFile = kmalloc(strlen_user(uChecksum->ipFile), GFP_KERNEL);
                if(IS_ERR(((struct job_checksum*)(kernelArgs->operation))->ipFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_checksum*)(kernelArgs->operation))->ipFile, uChecksum->ipFile, strlen_user(uChecksum->ipFile));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

                ((struct job_checksum*)(kernelArgs->operation))->hash_algo = kmalloc(strlen_user(uChecksum->hash_algo), GFP_KERNEL);
                if(IS_ERR(((struct job_checksum*)(kernelArgs->operation))->hash_algo))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_checksum*)(kernelArgs->operation))->hash_algo, uChecksum->hash_algo, strlen_user(uChecksum->hash_algo));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }
        }
        else if(kernelArgs->job_code == 4)
        {
                int i;
                struct job_concatfiles *uConcat = (struct job_concatfiles*)userArgs->operation;
                // the operation must be encryption
                kernelArgs->operation = (struct job_concatfiles*)kmalloc(sizeof(struct job_concatfiles), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_concatfiles*)(kernelArgs->operation), uConcat, sizeof(struct job_concatfiles));
                if(ret != 0)
                {
                        printk("in copy operation\n");
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_concatfiles*)(kernelArgs->operation))->files = (char**)kmalloc(uConcat->file_count * sizeof(char*), GFP_KERNEL);
                if(IS_ERR(((struct job_concatfiles*)(kernelArgs->operation))->files))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                for(i = 0; i < uConcat->file_count; i++)
                {
                        ((struct job_concatfiles*)(kernelArgs->operation))->files[i] = (char*)kmalloc(strlen_user(uConcat->files[i]), GFP_KERNEL);
                        if(IS_ERR(((struct job_concatfiles*)(kernelArgs->operation))->files[i]))
                        {
                                ret = -ENOMEM;
                                goto out;
                        }
                        ret = copy_from_user(((struct job_concatfiles*)(kernelArgs->operation))->files[i], uConcat->files[i], strlen_user(uConcat->files[i]));
                        if(ret != 0)
                        {
                                printk("in copy files\n");
                                ret = -EFAULT;
                                goto out;// free infile
                        }
                }

                ((struct job_concatfiles*)(kernelArgs->operation))->opFile = kmalloc(strlen_user(uConcat->opFile), GFP_KERNEL);
                if(IS_ERR(((struct job_concatfiles*)(kernelArgs->operation))->opFile))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_concatfiles*)(kernelArgs->operation))->opFile, uConcat->opFile, strlen_user(uConcat->opFile));
                if(ret != 0)
                {
                        printk("in copy output file\n");
                        ret = -EFAULT;
                        goto out;// free infile
                }
                /*printk("file count %d\n", ((struct job_concatfiles*)(kernelArgs->operation))->file_count);
                printk("file 1 %s\n", ((struct job_concatfiles*)(kernelArgs->operation))->files[0]);
                printk("file 2 %s\n", ((struct job_concatfiles*)(kernelArgs->operation))->files[1]);
                printk("file 3 %s\n", ((struct job_concatfiles*)(kernelArgs->operation))->files[2]);
                printk("output file %s\n", ((struct job_concatfiles*)(kernelArgs->operation))->opFile);*/
        }
        else if(kernelArgs->job_code == 5)
        {
                struct job_maintain_chpriority *uMcprio = (struct job_maintain_chpriority*)userArgs->operation;
                // the operation must be encryption


		kernelArgs->operation = (struct job_maintain_chpriority*)kmalloc(sizeof(struct job_maintain_chpriority), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_maintain_chpriority*)(kernelArgs->operation), uMcprio, sizeof(struct job_maintain_chpriority));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_maintain_chpriority*)(kernelArgs->operation))->user_job_id = kmalloc(strlen_user(uMcprio->user_job_id), GFP_KERNEL);
                if(IS_ERR(((struct job_maintain_chpriority*)(kernelArgs->operation))->user_job_id))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_maintain_chpriority*)(kernelArgs->operation))->user_job_id, uMcprio->user_job_id, strlen_user(uMcprio->user_job_id));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }

        }
        else if(kernelArgs->job_code == 6)
        {
                struct job_maintain_remove *uMrm = (struct job_maintain_remove*)userArgs->operation;
                // the operation must be encryption
                kernelArgs->operation = (struct job_maintain_remove*)kmalloc(sizeof(struct job_maintain_remove), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_maintain_remove*)(kernelArgs->operation), uMrm, sizeof(struct job_maintain_remove));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }

                ((struct job_maintain_remove*)(kernelArgs->operation))->user_job_id = kmalloc(strlen_user(uMrm->user_job_id), GFP_KERNEL);
                if(IS_ERR(((struct job_maintain_remove*)(kernelArgs->operation))->user_job_id))
                {
                        ret = -ENOMEM;
                        goto out;
                }
                ret = copy_from_user(((struct job_maintain_remove*)(kernelArgs->operation))->user_job_id, uMrm->user_job_id, strlen_user(uMrm->user_job_id));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;// free infile
                }
        }
        else if(kernelArgs->job_code == 8)
        {
                struct job_maintain_list *uMlist = (struct job_maintain_list*)userArgs->operation;
                // the operation must be encryption
                kernelArgs->operation = (struct job_maintain_list*)kmalloc(sizeof(struct job_maintain_list*), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_maintain_list*)(kernelArgs->operation), uMlist, sizeof(struct job_maintain_list));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }
        }
        else if(kernelArgs->job_code == 7)
        {
                struct job_maintain_count *uMcount = (struct job_maintain_count*)userArgs->operation;
                // the operation must be encryption
                kernelArgs->operation = (struct job_maintain_count*)kmalloc(sizeof(struct job_maintain_count*), GFP_KERNEL);
                if(IS_ERR(kernelArgs->operation))
                {
                        ret = -ENOMEM;
                        goto out;
                }

                ret = copy_from_user((struct job_maintain_count*)(kernelArgs->operation), uMcount, sizeof(struct job_maintain_count));
                if(ret != 0)
                {
                        ret = -EFAULT;
                        goto out;
                }
        }
out:
        return ret;
}
long isArgsValid(const struct job* uArgs)
{
	int ret = 0;
    
	//check for NULL user data
	if(uArgs == NULL)
	{    
		ret = -EINVAL;
		goto out;
	}
    //printk("submitjob  received arg %p, arglen: %d \n", arg, argLen);

/*    if(!access_ok(VERIFY_READ, arg, argLen)) //verify access may not be necessary because copy_from_user does that
        return -EFAULT;*/
		
	//check for valid job_code
	if((uArgs->job_code < 1) || (uArgs->job_code > 8))
	{
		ret = -EINVAL;
		goto out;
	}
	
	//check for NULL user_job_id
	if((uArgs->user_job_id) == NULL)
	{
		ret = -EINVAL;
		goto out;
	}
	
	//check for valid priority
	if((uArgs->priority < 0) || (uArgs->priority > 4))
	{
		ret = -EINVAL;
		goto out;
	}
	
	//check for valid bool is_atomic
	if((uArgs->is_atomic < 0) || (uArgs->is_atomic > 1)) /* what is is_atomic*/
	{
		ret = -EINVAL;
		goto out;
	}

	//check for NULL operation
	if(uArgs->operation == NULL)
	{    
		ret = -EINVAL;
		goto out;
	}
	
	//check for encrypt/decrypt
	if(uArgs->job_code == 1)
	{
		struct job_xcrypt *uXcrypt = (struct job_xcrypt*)uArgs->operation;
		
		//check for valid flag
		if((uXcrypt->flag < 0) || (uXcrypt->flag > 1))
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL input file
		if(uXcrypt->ipFile == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL key
		if(uXcrypt->key == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for invalid keylen
		if(uXcrypt->keylen != strlen_user((char*)uXcrypt->key))
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL output file
		if(uXcrypt->opFile == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
	}
	else if(uArgs->job_code == 2)
	{
		struct job_xcompress *uXcompress = (struct job_xcompress*)uArgs->operation;
		
		//check for valid flag
		if((uXcompress->flag < 0) || (uXcompress->flag > 1))
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL input file
		if(uXcompress->ipFile == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL key
		if(uXcompress->compression_algo == NULL) /* necessary?*/
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL output file
		if(uXcompress->opFile == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
	}
	else if(uArgs->job_code == 3)
	{
		struct job_checksum *uChecksum = (struct job_checksum*)uArgs->operation;
		
		//check for NULL input file
		if(uChecksum->ipFile == NULL)
		{    
			ret = -EINVAL;
			goto out;
		}
		
		//check for NULL key
		if(uChecksum->hash_algo == NULL || (strcmp(uChecksum->hash_algo,"md5"))) /* necessary?*/
		{    
			ret = -EINVAL;
			goto out;
		}

		//check for algo length
		if(uChecksum->algo_len != 16)
		{
			ret = -EINVAL;
			goto out;
		}
			
	}
	else if(uArgs->job_code == 4)
	{
		int i;
		struct job_concatfiles *uConcat = (struct job_concatfiles*)uArgs->operation;
		
		//check for NULL input files
		for(i = 0; i < uConcat->file_count; i++)
		{
			if(uConcat->files[i] == NULL)
			{
				ret = -EINVAL;
				goto out;
			}
		}
		
		//check for NULL output file
		if(uConcat->opFile == NULL) 
		{    
			ret = -EINVAL;
			goto out;
		}
	}
	else if(uArgs->job_code == 5 )
	{
		struct job_maintain_chpriority *uMcprio = (struct job_maintain_chpriority*)uArgs->operation;
		
		//check for NULL user_job_id
		if(uMcprio->user_job_id == NULL) 
		{    
			ret = -EINVAL;
			goto out;
		}
	}
	else if(uArgs->job_code == 6)
	{
		struct job_maintain_remove *uMrm = (struct job_maintain_remove*)uArgs->operation;
		
		//check for NULL user_job_id
		if(uMrm->user_job_id == NULL) 
		{    
			ret = -EINVAL;
			goto out;
		}
	}
out:    
	return ret;
}




static void submitjob_recv_msg(struct sk_buff *skb)
{
	int ret, wait_flag = 0;
        struct job *kjob;
    //  struct job *ujob;
        struct nlmsghdr *nlh;
	struct job_result *rjob;

        printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

        //get data from user
        nlh = (struct nlmsghdr *)skb->data;

        /*printk("msg data %p\n", &((struct job*)(nlmsg_data(nlh)))->job_code);
        printk("mag job code %d\n", ((struct job*)(nlmsg_data(nlh)))->job_code);
        printk("user job id addr %p\n", ((struct job*)(nlmsg_data(nlh)))->user_job_id);
        printk("user job id %s\n", ((struct job*)(nlmsg_data(nlh)))->user_job_id);*/


        /* all args are valid user virtual memory locations  and hold good values*/
        /* now copy the data from user space to kernel space */
        kjob = (struct job*)kmalloc(sizeof(struct job), GFP_KERNEL);
        if(IS_ERR(kjob))
        {
                ret = -ENOMEM;
                goto out_err;
        }

        //kjob = (struct job*)(nlmsg_data(nlh));
	memcpy(kjob,(struct job*)(nlmsg_data(nlh)), sizeof(struct job));

	kjob->pid = nlh->nlmsg_pid;
        ret = isArgsValid((struct job*)(nlmsg_data(nlh)));
        printk("after is valid %d\n", ret);
        if(ret < 0)
                goto out_err;

		
        ret = copyFromUserland((struct job*)(nlmsg_data(nlh)), kjob);
        printk("ret after copy from user %d\n", ret);
        if(ret < 0)
                goto out_err;

        printk("after copy from user\n");
      
	
        if(kjob != NULL){
                printk("In Syssubmit %s\n",kjob->user_job_id);
        }
	kjob->pid = nlh->nlmsg_pid;
	if(kjob->job_code >= 5){
        wait_flag = 1;
		printk("jobcode is %d\n",kjob->job_code);
		printk("jobcount is %d\n",jobCount);
                process_job(nl_sk, kjob);
		goto out;
	}

	globaljob = kjob;
	/****************************   Submitting request ***********************************/
        if(producer_task){
                wake_up_process(producer_task);
        }
        else{
		printk("Error eagain\n");
		ret = -EAGAIN;
		goto out_err;
	}
	
out:
	return;	
out_err:
	printk("ret value at end%d\n", ret);
        rjob = (struct job_result*)kmalloc(sizeof(struct job_result), GFP_KERNEL);
	rjob->user_job_id = (char*)kmalloc(strlen(kjob->user_job_id)+1, GFP_KERNEL);
	memcpy(rjob->user_job_id, kjob->user_job_id, strlen(kjob->user_job_id));
	*(rjob->user_job_id + strlen(kjob->user_job_id) + 1) = '\0';
	rjob->return_value = ret;
	rjob->return_buf = NULL;
	result_send_msg(nl_sk, rjob, nlh->nlmsg_pid,wait_flag);
        return;

}

static int __init init_submitjob(void)
{
	//	int result;
    	printk("Entering: %s\n", __FUNCTION__);
	jobCount = 0;
        producer_task = kthread_create(&func_produce,(void *)(&globaljob),"producer_thread");
       	if(IS_ERR(producer_task))
        	return -EAGAIN;        
       	consumer_task = kthread_create(&func_consume,NULL,"consumer_thread");
       	if(IS_ERR(consumer_task)){
        	return -EAGAIN;   
	}     
	INIT_LIST_HEAD(&(queuehead.job_list_member));                          // Initializing the head of the job queue
        queuehead.currentJob = NULL;

        mutex_init(&qmutex);                                                    // Initializing the mutex for the job queue and jobCount
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk) {
        	printk(KERN_ALERT "Error creating socket.\n");
        	return -10;
    	}

	return 0;
}
static void  __exit exit_submitjob(void)
{
	struct qStruct *tmp;
        struct list_head *pos, *q;
	int ret = 0;
	//printk(KERN_INFO "exiting submitjob module\n");
	ret = kthread_stop(producer_task);
        if(ret == 0){
        	//printk("Producer Thread stopped!!\n");
        }
        if(consumer_task){
                ret = kthread_stop(consumer_task);
               	if(ret == 0){
                        //printk("Consumer Thread stopped!!\n");
                }
       	}
        list_for_each_safe(pos, q, &queuehead.job_list_member){
        	tmp= list_entry(pos, struct qStruct, job_list_member);
                printk("freeing item \n");
               	list_del(pos);
                kfree(tmp);
        }
                mutex_destroy(&qmutex);                                                 // Initializing the mutex for the job queue

    	netlink_kernel_release(nl_sk);
}
module_init(init_submitjob);
module_exit(exit_submitjob);
MODULE_LICENSE("GPL");
