#ifndef PROCESSJOB_H_  /*Guard*/
#define PROCESSJOB_H_

#include "sys_submitjob.h"
#include "perform_job.h"
#include <asm/uaccess.h>
#include <asm/siginfo.h>

#define SIG_TEST 44

void result_send_msg(struct sock *nl_sk, struct job_result* rjob, int pid, int wait_flag)
{
        struct nlmsghdr *nlh;
        struct sk_buff *skb_out;
        int msg_size;
        int ret = 0;
	char *msg;
	struct siginfo info;
        struct task_struct *t;
    printk("before result malloc\n");
	char *result = (char*)kmalloc(4, GFP_KERNEL);
    printk("after result malloc\n");
	/*struct job *kjob = gjobs->globaljob;
	printk("After kjob allcaiton %d\n",kjob->job_code);
	struct job *ujob = gjobs->globalujob;
	printk("After ujob allcaiton \n");
       // char *msg = "Finished processing request. Check return value.";
	
        result = (char*)kmalloc(sizeof(char*), GFP_KERNEL);
        if(IS_ERR(result))
        {
                printk(KERN_ERR "Failed to allocate memeory to result\n");
                goto out_exit;
        }

	printk("process result %d\n", ret);
        *result = ret+'0';
//        printk("return value address %p\n", ujob->return_value);
        printk("return char %s\n", result);
	printk("return int %d\n", *result-'0');


//	ret = access_ok(VERIFY_WRITE, (void *)ujob->return_value, 4);
  //      printk("ACCESS OK result : %d\n", ret);

//	ret =  __copy_to_user((void*)kjob->return_value, (const void*)result, 4);

        ret = copy_to_user(ujob->return_value, result, strlen(result));
        printk("bytes copied after copy_to_user %d\n", ret);
	if(IS_ERR(ERR_PTR(ret)))
        {
                printk(KERN_ERR "Failed to copy to user\n");
                goto out;
        }
*/

	printk("user ob len %d\n", strlen(rjob->user_job_id));
        if(rjob->return_buf != NULL)
        {
		printk("inside not null");
         	printk("uer return bu %d\n", strlen(rjob->return_buf));
	        msg = (char*)kmalloc(13 + strlen(rjob->user_job_id) + strlen(rjob->return_buf), GFP_KERNEL);
        }else
        {
               msg = (char*)kmalloc(13 + strlen(rjob->user_job_id), GFP_KERNEL);
        }


	*msg = rjob->return_value+'0';
	*(msg + 4) = '\0';
	*result = strlen(rjob->user_job_id)+'0';
	printk("result %d\n",(int)(*result));
	printk("result %d\n", *result-'0');
	msg = strncat(msg, result, 4);
	*(msg + 8) = '\0';
	printk("msg b %s\n", msg);
	printk("msg l %d\n", strlen(msg));
	msg = strncat(msg, rjob->user_job_id, strlen(rjob->user_job_id));
	*(msg + 8+strlen(rjob->user_job_id)) = '\0';
	printk("msg %s\n", msg);
	printk("msg l %d\n", strlen(msg));
        if(rjob->return_buf != NULL)
	      *result = strlen(rjob->return_buf)+'0';
	else 
		*result = 0+'0';
	msg = strcat(msg, result);
	if(rjob->return_buf!=NULL)
	{
		msg = strncat(msg, rjob->return_buf, strlen(rjob->return_buf));
		*(msg + 13 + strlen(rjob->user_job_id) + strlen(rjob->return_buf)) = '\0';
        }
	else
	{
		*(msg + 13 + strlen(rjob->user_job_id)) = '\0';
	}
	msg_size = strlen(msg);

        // printk("pid %d\n", pid);
        /* consumer should free prod_job if not maintenace task? */
        skb_out = nlmsg_new(msg_size, 0);
        if(!skb_out) {
                printk(KERN_ERR "Failed to allocate new skb\n");
                goto out_exit;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        strncpy(nlmsg_data(nlh), msg, msg_size);
        printk("sent message to pid %d\n", pid);
	
	if(nl_sk == NULL)
		printk("INSIDE NULL!!!!");
        ret = nlmsg_unicast(nl_sk, skb_out, pid);
        printk("unicast return %d\n", ret);
	if (ret < 0)
                printk(KERN_INFO "Error while sending back to user\n");

	//send signal
    if(wait_flag == 1){
    printk("Calling the signal\n");
	memset(&info, 0, sizeof(struct siginfo));
        info.si_signo = SIG_TEST;
        info.si_code = SI_QUEUE;
        info.si_int = ret;

        rcu_read_lock();
        t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
        if(t == NULL){
            printk("no such pid\n");
        }
        rcu_read_unlock();
        ret = send_sig_info(SIG_TEST, &info, t);    //send the signal
        if (ret < 0) {
             printk("error sending signal\n");
        }
        }
out_exit:
	kfree(result);
	kfree(rjob);
        return;
}



void process_job(struct sock *nl_sk, struct job *currProcJob){
    struct job_result *rjob = (struct job_result*)kmalloc(sizeof(struct job_result), GFP_KERNEL);
    printk("in process job\n");
    rjob->user_job_id = (char*)kmalloc(strlen(currProcJob->user_job_id) +1, GFP_KERNEL);
        memcpy(rjob->user_job_id, currProcJob->user_job_id, strlen(currProcJob->user_job_id));
        *(rjob->user_job_id + strlen(currProcJob->user_job_id)) = '\0';

    int jcode =currProcJob->job_code;int wait_flag;
    struct job_maintain_remove *subjob_del;
    struct job_maintain_chpriority *subjob_priority;
    struct job_maintain_list *subjob_list;
    struct job_maintain_count *subjob_count;
    void *op = currProcJob->operation;
    if(jcode == 1)
        perform_xcrypt(currProcJob, rjob);
    else if(jcode == 2)
            perform_xcompress(currProcJob, rjob);   
    else if(jcode == 3)
        perform_checksum((struct job_checksum*)(currProcJob->operation), rjob, currProcJob->is_atomic);
    else if(jcode == 5){
        subjob_del = (struct job_maintain_remove *)(op);
        printk("DELETE JOB\n");
        perform_deljob(subjob_del->user_job_id,rjob);
    }
    else if(jcode == 6){
        subjob_priority = (struct job_maintain_chpriority *)(op);
        printk("Changing priority\n");
        perform_chpriority(subjob_priority->user_job_id,currProcJob->priority,rjob);            
    }       
    else if(jcode == 7){
        subjob_count = (struct job_maintain_count *)(op);
        printk("Counting\n");
        perform_count(subjob_count->job_count,rjob);            
    }
    else if(jcode  == 8){
        subjob_list = (struct job_maintain_list *)(op);
        printk("Listing\n");
        perform_list(subjob_list->buf,subjob_list->buflen,rjob);        
    }       
    printk("CURRENT Job code is %d\n",currProcJob->job_code);
    
/*  rjob->user_job_id = (char*)kmalloc(strlen(currProcJob->user_job_id) +1, GFP_KERNEL);
    memcpy(rjob->user_job_id, currProcJob->user_job_id, strlen(currProcJob->user_job_id));
    *(rjob->user_job_id + strlen(currProcJob->user_job_id) + 1) = '\0';*/
    if(jcode <  5)
        wait_flag = 1;
    else
        wait_flag = 0;
    printk("wait_flaf %d\n", wait_flag);
       result_send_msg(nl_sk, rjob, currProcJob->pid,wait_flag);
        return;
    
        
}



#endif
