#ifndef PERFORMJOB_H_  /*Guard*/
#define PERFORMJOB_H_

#include <linux/crypto.h>
#include <linux/unistd.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/raid/pq.h>
	
#define ENCRYPT_PASSPHRASE_LEN 16
#include "sys_submitjob.h"

struct qStruct{
        struct job *currentJob;
        struct list_head job_list_member;
};
struct qStruct queuehead;
static int jobCount;
struct mutex qmutex;
void perform_count(int *ujob_count, struct job_result *rjob){			//need to copy_to_user the int value
	int rc = 0;
    mutex_lock(&qmutex);
	rc = copy_to_user(ujob_count,&jobCount,sizeof(int));
    printk("In coiunt fn job count is %d\n",jobCount);
    printk("pointer is %p\n",ujob_count);	
	mutex_unlock(&qmutex);	
	rjob->return_value = 0;
    rjob->return_buf = NULL;			
	return;
}

void perform_list(char *ubuf,int buflen, struct job_result *rjob){				// need to copy_to_user the buffer and buff_len
	struct qStruct  *qtmp;
	int ctu_ret = 0,ret = 0,count = 0, cur_len = 0;
	char *cur_user_id;
	char *kbuf = (char *)kmalloc(buflen,GFP_KERNEL);char *tmp_buf;
	printk("buflen is %d\n",buflen);
	if(IS_ERR(kbuf) || kbuf == NULL){
		ret = -ENOMEM;	
		goto out;	
	}	
	tmp_buf = kbuf;
	mutex_lock(&qmutex);
	list_for_each_entry(qtmp, &(queuehead.job_list_member), job_list_member){
		cur_user_id = qtmp->currentJob->user_job_id;
		printk("cur user is %s\n",cur_user_id);	
		cur_len = strlen(cur_user_id); 
		printk("curr len is %d\n",cur_len);
		count = count + cur_len;
		if(count >= buflen-1){
			break;
		}
		memcpy(kbuf,cur_user_id,cur_len);									
		kbuf = kbuf + cur_len;
		count++;
		if(count+1 >= buflen-1){
			break;
		}
		*(kbuf) = '\n';
		kbuf++;
	}
	printk("ubuf ptr is %p\n",ubuf);
	mutex_unlock(&qmutex);		
	*(kbuf) = '\0';
	ctu_ret = copy_to_user(ubuf,tmp_buf,strlen(tmp_buf));	
	printk("ubuf is %s\n",ubuf);
	if(ctu_ret > 0){
		printk("ctu returned %d\n",ctu_ret);
		ret = -EAGAIN;  		
	}	
	printk("kbuf is %s\n",tmp_buf);
	if(kbuf)
		kfree(kbuf);
	out:
	rjob->return_value = ret;
    rjob->return_buf = NULL;
	return;
}
void perform_deljob(char *id, struct job_result *rjob){
	int ret = 0, flag = 0;
	struct list_head *pos, *q;
        struct qStruct *tmp;
        struct job* cjob;
	mutex_lock(&qmutex);
	printk("the job to be remooved is %s\n",id);
	list_for_each_safe(pos, q, &(queuehead.job_list_member)){
		tmp= list_entry(pos, struct qStruct, job_list_member);
                cjob = tmp->currentJob;
        	printk("BUFFER %d\n", cjob->priority);
                if(strcmp(id,cjob->user_job_id) == 0){
			list_del(pos);
                        kfree(tmp);		
                        flag = 1;
                        printk("Deleting %s\n",id);
                        break;
               	}
        }
	if(flag == 1)
		jobCount--;
	mutex_unlock(&qmutex);	
	if(flag == 0)
		ret = -EINVAL;  
	rjob->return_value = ret;
	rjob->return_buf = NULL;
	return;	
	
}

void perform_chpriority(char *id,int prior, struct job_result *rjob){
	int ret = 0, flag = 0;
	struct list_head *pos, *q;
        struct qStruct *tmp;
	struct qStruct  *qtmp;	
	struct job *cjob;
	mutex_lock(&qmutex);							// LOCKING because we are accessing the Queue
	list_for_each_safe(pos, q, &(queuehead.job_list_member))                // Iterating through jobs in the queue
        {
        	tmp= list_entry(pos, struct qStruct, job_list_member);
                cjob = tmp->currentJob;
		if(strcmp(id,cjob->user_job_id) == 0){
                        list_del(pos);
                        //kfree(tmp);
                        flag = 1;
                        printk("Deleting %s\n",id);
                        break;
                }

        }
	if(flag == 0){
		ret = -EINVAL;
		goto out;
	}
	else{
		flag = 0;
		tmp->currentJob->priority = prior;
		cjob = tmp->currentJob;
		list_for_each_entry(qtmp, &(queuehead.job_list_member), job_list_member){       // inserting into the queue according to prioirty
                	printk("BUFFER in  chpriority%d\n", qtmp->currentJob->priority);
                        if(cjob->priority > qtmp->currentJob->priority){
                        	list_add(&(tmp->job_list_member),&(qtmp->job_list_member));
                                flag = 1;
                                printk("Breaking in chpriority\n");
                                break;
                        }
                }
                if(flag == 0){
                	list_add_tail(&(tmp->job_list_member),&(queuehead.job_list_member));
                        printk("Adding when jobCount is NOT ZERO in CHPRIOR\n");
                }	
	}
	out:
        mutex_unlock(&qmutex);
		rjob->return_value = ret;
		rjob->return_buf = NULL;
		return;
		

}

static int md5_in_kernel(char *hash_value, char *passwrd, int passwrd_len)
{
        struct scatterlist sg;
        struct hash_desc desc;
        int error_no = 0;
        sg_init_one(&sg, passwrd, (size_t)passwrd_len);
        desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
        error_no = crypto_hash_init(&desc);
        if(error_no == 0)
        {
                error_no = crypto_hash_update(&desc,&sg, (size_t)passwrd_len);
        if(error_no == 0)
                {
                        error_no = crypto_hash_final(&desc, hash_value);
                        goto return_line;
                }
                else goto return_line;

        }
        return_line:
                crypto_free_hash(desc.tfm);
                return error_no;
}
static int decrypt(const void *key, int key_len, void *dst, size_t *dst_len,const void *src, size_t src_len)
{
        struct scatterlist sg_out,sg_in;
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)",0, CRYPTO_ALG_ASYNC);
        struct blkcipher_desc desc; int ret = 0;
        if(IS_ERR(tfm))
                return PTR_ERR(tfm);
        desc.tfm = tfm ;
        desc.flags = 0;
        sg_init_one(&sg_in,src,src_len);
        sg_init_one(&sg_out, dst, src_len);
        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        ret = crypto_blkcipher_decrypt(&desc, &sg_out, &sg_in, src_len);
        if (ret < 0)
        {
                ret = -EAGAIN;
                goto out_sg;
        }
        *dst_len = src_len;
        out_sg:
                 crypto_free_blkcipher(tfm);
        return ret;
}
static int encrypt(const void *pass,int pass_len,void *out_buff,size_t * out_len,const void *buff_read, size_t read_len)
{
        struct scatterlist sg_in, sg_out;
        struct blkcipher_desc desc;int ret = 0;
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
        if(IS_ERR(tfm)) return PTR_ERR(tfm);
        desc.tfm = tfm;
        desc.flags = 0;
        *out_len = read_len;
        sg_init_one(&sg_in,buff_read,read_len);
        sg_init_one(&sg_out,out_buff,*out_len);
        crypto_blkcipher_setkey((void *)tfm, pass, pass_len);
        ret = crypto_blkcipher_encrypt(&desc, &sg_out, &sg_in,read_len);
        if(ret < 0)
                ret = -EAGAIN;
        crypto_free_blkcipher(tfm);
        return ret;
}
struct file* file_open(const char *filename, int mode, int accessrights)
{
	 struct file *filp;
	 filp = filp_open(filename, mode, accessrights);
    	 
	 return filp; 
}

int file_isfile(struct file *filp)
{
	if(!S_ISREG(filp->f_path.dentry->d_inode->i_mode))
        	return -EISDIR;
	return 0;
}

int file_readable(struct file *filp)
{
	if (!filp->f_op->read)
		return -EPERM;
	return 0;
}

int file_writable(struct file *filp)
{
	if(!filp->f_op->write)
		return -EPERM;
	return 0;
}

void perform_xcrypt(struct job *cjob, struct job_result *rjob){
    //mdelay(40000);
	int i = 0,ret = 0, kern_keylen = 0, atomicity = 0,is_encrypt = 0,len1 = 0;
	int read_bytes = 0, write_bytes = 0;int len = PAGE_SIZE;
	mm_segment_t oldfs;
	struct job_xcrypt *xjob = (struct job_xcrypt*)(cjob->operation);
	struct file* outfile; struct file* infile; struct file *out_tmpfile;
	struct inode *inp_inode;char *double_pass_kernel; char *buff_read;  char *out_buff; char *kern_key;size_t out_buff_len = 0;char *tmp_filename;
	struct dentry *out_dentry = NULL; struct dentry *tmp_dentry = NULL;
	struct inode *par_tmp = NULL; struct inode *par_out = NULL;
	atomicity = cjob->is_atomic;
	printk("input filename is %s\n",xjob->ipFile);
	printk("output filename is %s\n",xjob->opFile);
	infile = file_open(xjob->ipFile,O_RDONLY,0); 
	if(!infile || IS_ERR(infile)){
		ret = (int) PTR_ERR(infile);
		printk("ERROR %d\n",ret);
		goto out_err;
	}
	printk("input File open done\n");
	if(!file_isfile(infile) && !file_readable(infile)){
		printk("File present and readable\n");						
		
	}
	else{
		ret = -ENOENT;
		goto close_inp_file;			
	}
	/************************Input file checks done**********************************/
	
	inp_inode = infile->f_path.dentry->d_inode;
	if(inp_inode == NULL){
		ret = -ENOENT;
		goto close_inp_file;
	}
	outfile = file_open(xjob->opFile,O_CREAT | O_WRONLY | O_TRUNC, inp_inode->i_mode); 
	if(!outfile || IS_ERR(outfile)){
		ret = (int) PTR_ERR(outfile);
		printk("ERROR %d\n",ret);
		goto close_inp_file;
	}
	printk("Output File open done\n");
	if(!file_isfile(outfile) && !file_readable(outfile)){
		printk("Output File present and readable\n");						
	}
	else{
		ret = -ENOENT;
		goto close_out_file;			
	}
	/*******************Output  file checks done ***************************************/
	
	if(atomicity == 1){					// Open a tmp file and make it output file
	
	len1 = strlen(xjob->opFile); 
	tmp_filename = kmalloc(len1+5,GFP_KERNEL); 
	memcpy(tmp_filename,xjob->opFile,len1);			// Forming tmp filename
	tmp_filename[len1] = '.';tmp_filename[len1+1] = 't';tmp_filename[len1+2] = 'm';tmp_filename[len1+3] = 'p';tmp_filename[len1+4] = '\0';		
	out_tmpfile = file_open(tmp_filename,O_CREAT | O_WRONLY | O_TRUNC, inp_inode->i_mode);
	if(tmp_filename)					// Freeing memory allocated to tmp_filename
		kfree(tmp_filename);
        if(!out_tmpfile || IS_ERR(out_tmpfile)){
                ret = (int) PTR_ERR(out_tmpfile);
                printk("ERROR %d\n",ret);
                goto close_out_file;
        }
        printk("Output File open done\n");
        if(!file_isfile(out_tmpfile) && !file_readable(out_tmpfile)){
                printk("Output File present and readable\n");
        }
        else{
                ret = -ENOENT;
                goto close_out_tmpfile;
        }
	
	}
	else{						// If the operation need not be atomic
		out_tmpfile = outfile;
	}
	/************************Output tmp file checks done if atomicity is 1**********************************/ 
	kern_keylen = xjob->keylen-1;
	kern_key = xjob->key;	
	double_pass_kernel = kmalloc(kern_keylen+1,GFP_KERNEL);
        if(!double_pass_kernel)
        {
        	ret = -EFAULT;
                goto close_out_tmpfile;
        }
	
        ret = md5_in_kernel(double_pass_kernel,xjob->key,kern_keylen);  // hash the password sent by user prog.
        if(ret < 0){
        	ret = -ECANCELED;
                goto free_double_pass;
        }
        double_pass_kernel[kern_keylen] = '\0';
	printk("double password is %s\n",double_pass_kernel);
	

	/**************************** Getting the double password done***************************/

	is_encrypt = xjob->flag; 
	
	oldfs = get_fs();
        buff_read = kmalloc((len)*sizeof(char),GFP_KERNEL);                     // allocating memory for the inpit buffer
        if(!buff_read){
                ret = -EFAULT;
                goto free_double_pass;
        }
        out_buff = kmalloc((len)*sizeof(char),GFP_KERNEL);                      // allocating memory for the output buffer
        if(!out_buff){
                ret = -EFAULT;
                goto free_buff;
        }
	printk("After allocatig buff_read and out_buff\n");
	i = 0;
	set_fs(KERNEL_DS);
        while(1){
                if(i == 0)                                                              // First check if encryption / decryption can be done
                {
                        infile->f_pos = 0;        out_tmpfile->f_pos = 0;
                        if(is_encrypt){                                                              // If "encrypt" write hashed key into the o/p file
                                write_bytes = out_tmpfile->f_op->write(out_tmpfile, (void *)double_pass_kernel, ENCRYPT_PASSPHRASE_LEN, &out_tmpfile->f_pos);
                                if(write_bytes < 0){
                                        ret = -EINVAL;
                                        goto free_out_buff;
                                }
                        }
                        else{                                                                                   // If "decrypt"
                                read_bytes = infile->f_op->read(infile,(void *)buff_read, ENCRYPT_PASSPHRASE_LEN, &infile->f_pos);
                                if(read_bytes < 0){
                                        ret = -EINVAL;
                                        goto free_out_buff;
                                }
                                buff_read[ENCRYPT_PASSPHRASE_LEN] = '\0';
                                if(strcmp(double_pass_kernel, buff_read) != 0){         // WRONG ENCRYPTION/ DECRYPTION OPTIONS, hashed keys do not match
                                        ret = -ECANCELED;
                                        goto free_out_buff;
                                }
                        }
                }
		printk("Actual reading nd writing\n");
                /* ACTUAL READING AND WRITING STARTS HERE. ENCRYPTION AND DECRYPTION SHOULD BE HERE*/
                read_bytes = infile->f_op->read(infile, (void *)buff_read, len-1, &infile->f_pos);
                if(read_bytes < 0){
                        ret = -EINVAL;
                        goto free_out_buff;
                }
                buff_read[read_bytes] = '\0';
                printk("after read %d\n", read_bytes);
		if(read_bytes == 0){    goto free_double_pass;}
                if(is_encrypt){                       
                       // ENCRYPTing
			printk("inside is encrypt\n");  
                      ret = encrypt((const void *)kern_key,kern_keylen,(void *)out_buff,&out_buff_len,(const void *)buff_read, (size_t)(read_bytes));
                        out_buff[out_buff_len] = '\0';
                        printk("after enncrypt\n");
			if(ret < 0){
                                ret = -ECANCELED;
                                goto free_out_buff;
                        }
                }
                else{                                                                   // DECRYPTing
			printk("inside is decrypt\n");
                        ret = decrypt((const void *)kern_key,kern_keylen,(void *)out_buff,&out_buff_len,(const void *)buff_read, (size_t)(read_bytes));
                        out_buff[out_buff_len] = '\0';
			printk("after decrypt\n");
                        if(ret < 0){
                                ret = -ECANCELED;
                                goto free_out_buff;
                        }
                }
                write_bytes = out_tmpfile->f_op->write(out_tmpfile, (void *)out_buff, out_buff_len, &out_tmpfile->f_pos);
		printk("write bytes are %d\n",write_bytes);	
                if(read_bytes < len-1)  break;                                          // File (reading,encryptin)g/(writng, decrypting)  done
                i++;
        }
        set_fs(oldfs);
	if(atomicity == 1){
		par_tmp = out_tmpfile->f_path.dentry->d_parent->d_inode;
	        tmp_dentry = out_tmpfile->f_path.dentry; 
		par_out = outfile->f_path.dentry->d_parent->d_inode;
	        out_dentry = outfile->f_path.dentry;	
		len = vfs_rename(par_tmp,tmp_dentry, par_out, out_dentry, NULL, 0);
                if(len < 0)                           // if rename fails delete the tmpfile
                {
                	ret = -ECANCELED  ;
                        len = vfs_unlink(par_tmp, tmp_dentry,NULL);
                }
		
	}
	
	//////////// KEEP IN MIND is_atomic //////////////////////////////////

	/************************** Labels *******************************************/
	free_out_buff:
		if(out_buff) kfree(out_buff);	
	free_buff:
		if(buff_read) kfree(buff_read);	
	free_double_pass:
		if(double_pass_kernel) kfree(double_pass_kernel);	
	close_out_tmpfile:
		if(out_tmpfile)	filp_close(out_tmpfile,NULL);		
	close_out_file:
		if(outfile)	filp_close(outfile,NULL);		
	close_inp_file:
		if(infile)	filp_close(infile,NULL);		
	out_err:
		printk("Copying Final\n");
		rjob->return_value = ret;
		rjob->return_buf = NULL;
		return;	


}

void perform_xcompress(struct job *cjob, struct job_result *rjob)
{
    int ret = 0;
    struct job_xcompress *xcjob = (struct job_xcompress*)(cjob->operation);
    int atomicity = cjob->is_atomic;
    struct dentry *out_dentry = NULL; struct dentry *tmp_dentry = NULL;
    struct inode *par_tmp = NULL; struct inode *par_out = NULL;

    /*printk("compress flag passed: %d\n", xcjob->flag);
    printk("input file passed: %s\n", xcjob->ipFile);
    printk("output file passed: %s\n", xcjob->opFile);
    printk("compression algorithm passed: %s\n", xcjob->compression_algo);
*/
    struct file* outfile; struct file* infile; struct file *out_tmpfile;struct inode *inp_inode;char *tmp_filename;
    infile = file_open(xcjob->ipFile,O_RDONLY,0);
    if(!infile || IS_ERR(infile)){
        ret = (int) PTR_ERR(infile);
        printk("ERROR %d\n",ret);
        goto out_err;
    }
    printk("input File open done\n");
    if(!file_isfile(infile) && !file_readable(infile)){
        printk("File present and readable\n");

    }
    else{
        ret = -ENOENT;
        goto close_inp_file;
    }


    inp_inode = infile->f_path.dentry->d_inode;
    if(inp_inode == NULL){
        ret = -ENOENT;
        goto close_inp_file;
    }
    outfile = file_open(xcjob->opFile,O_CREAT | O_WRONLY | O_TRUNC, inp_inode->i_mode);
    if(!outfile || IS_ERR(outfile)){
        ret = (int) PTR_ERR(outfile);
        printk("ERROR %d\n",ret);
        goto close_inp_file;
    }
    printk("Output File open done\n");
    if(!file_isfile(outfile) && !file_readable(outfile)){
        printk("Output File present and readable\n");
    }
    else{
        ret = -ENOENT;
        goto close_out_file;
    }

    /*************atomicity*************************************/

     if(atomicity == 1){                 // Open a tmp file and make it output file

    int len1 = strlen(xcjob->opFile);
    tmp_filename = kmalloc(len1+5,GFP_KERNEL);
    memcpy(tmp_filename,xcjob->opFile,len1);         // Forming tmp filename
    tmp_filename[len1] = '.';tmp_filename[len1+1] = 't';tmp_filename[len1+2] = 'm';tmp_filename[len1+3] = 'p';tmp_filename[len1+4] = '\0';
    out_tmpfile = file_open(tmp_filename,O_CREAT | O_WRONLY | O_TRUNC, inp_inode->i_mode);
    if(tmp_filename)                    // Freeing memory allocated to tmp_filename
        kfree(tmp_filename);
        if(!out_tmpfile || IS_ERR(out_tmpfile)){
                ret = (int) PTR_ERR(out_tmpfile);
                printk("ERROR %d\n",ret);
                goto close_out_file;
        }
        printk("Output File open done\n");
        if(!file_isfile(out_tmpfile) && !file_readable(out_tmpfile)){
                printk("Output File present and readable\n");
        }
        else{
                ret = -ENOENT;
                goto close_out_tmpfile;
        }

    }
    else{                       // If the operation need not be atomic
        out_tmpfile = outfile;
    }


    if(xcjob->flag == 1)
    {
        // compress
         //printk(" compressing the file\n");

	 int fileSize = infile->f_path.dentry->d_inode->i_size;
         char *read_buffer;
	 size_t bytesRead = 0;
	 struct crypto_comp *tfm;
	 unsigned int finalLength;
	 u8* dest;
	 mm_segment_t oldfs;
	 

	 infile->f_pos = 0;
         out_tmpfile->f_pos = 0;

	 printk("in compression\n");

	 oldfs = get_fs();// store the prev transalation so that we dont mess later
         set_fs(KERNEL_DS);// the read_buffer points to kernel , no need of translation
         

         read_buffer = (char *) kmalloc(fileSize, GFP_KERNEL);
         if(!read_buffer || IS_ERR(read_buffer))
         {
             ret = -ENOMEM;
             goto close_out_tmpfile; // unlink the output file
         }
         memset(read_buffer, 0, fileSize);

         bytesRead = infile->f_op->read(infile, read_buffer, fileSize, &infile->f_pos);

         tfm = crypto_alloc_comp("lzo", 0, CRYPTO_ALG_ASYNC);

        if(!tfm || IS_ERR(tfm))
        {
            ret = PTR_ERR(tfm);
            printk("error allocating crypto context for compression: %d", ret);
            if(read_buffer) kfree(read_buffer);
            set_fs(oldfs);
            goto close_out_tmpfile;

        }

        dest = (u8 *) kmalloc(fileSize*2, GFP_KERNEL);
        if(!dest)
        {
            ret = -ENOMEM;
            if(read_buffer) kfree(read_buffer);
            set_fs(oldfs);
            goto close_out_tmpfile;
        }

        memset(dest, 0, fileSize*2);
        finalLength = fileSize*2;
        ret  = crypto_comp_compress(tfm, (u8 *)read_buffer, bytesRead, dest, &finalLength);
        printk(" return code from compression:%d, final length :%d", ret, finalLength);

       // write the dest to output file

       if(out_tmpfile->f_op->write(out_tmpfile, dest, finalLength, &out_tmpfile->f_pos) <= 0 )
        {
            ret = -EIO;// if writing failed, free read buffer, write buffer and felete output filei
            if(read_buffer) kfree(read_buffer);
            if(dest) kfree(dest);
        }
       else
        {
           if(read_buffer) kfree(read_buffer);
           if(dest) kfree(dest);
        }


       set_fs(oldfs);

    }
    else
    {
	 int fileSize;
	 char *read_buffer;
	 size_t bytesRead = 0;
	 struct crypto_comp *tfm;
	 u8* dest;
	 unsigned int finalLength;
	 mm_segment_t oldfs;

       

	 printk(" decompressing the file\n");
         //decompress
         infile->f_pos = 0;
         out_tmpfile->f_pos = 0;

         
         oldfs = get_fs();// store the prev transalation so that we dont mess later
         set_fs(KERNEL_DS);// the read_buffer points to kernel , no need of translation
         fileSize = infile->f_path.dentry->d_inode->i_size;

         read_buffer = (char *) kmalloc(fileSize, GFP_KERNEL);
         if(!read_buffer || IS_ERR(read_buffer))
         {
             ret = -ENOMEM;
             goto close_out_tmpfile; // unlink the output file
         }
         memset(read_buffer, 0, fileSize);

         bytesRead = 0;
         bytesRead = infile->f_op->read(infile, read_buffer, fileSize, &infile->f_pos);


         tfm = crypto_alloc_comp("lzo", 0, CRYPTO_ALG_ASYNC);

        if(!tfm || IS_ERR(tfm))
        {
            ret = PTR_ERR(tfm);
            printk("error allocating crypto context for compression: %d", ret);
            if(read_buffer) kfree(read_buffer);
            set_fs(oldfs);
            goto close_out_tmpfile;
            // free read buf
        }

        dest = (u8 *) kmalloc(fileSize*2, GFP_KERNEL);
        if(!dest)
        {
            ret = -ENOMEM;
            if(read_buffer) kfree(read_buffer);
            set_fs(oldfs);
            goto close_out_tmpfile;
        }

        memset(dest, 0, fileSize*2);
        finalLength = fileSize*2;
        ret  = crypto_comp_decompress(tfm, (u8 *)read_buffer, bytesRead, dest, &finalLength);
        printk(" return code from decompression:%d, final length :%d", ret, finalLength);

       // write the dest to output file

       if(out_tmpfile->f_op->write(out_tmpfile, dest, finalLength, &out_tmpfile->f_pos) <= 0 )
        {
            ret = -EIO;// if writing failed, free read buffer, write buffer and felete output file
            if(read_buffer) kfree(read_buffer);
            if(dest) kfree(dest);

        }
        else
        {
           if(read_buffer) kfree(read_buffer);
           if(dest) kfree(dest);
        }

       set_fs(oldfs);

    }


    if(atomicity == 1){
        
	int len;
	par_tmp = out_tmpfile->f_path.dentry->d_parent->d_inode;
        tmp_dentry = out_tmpfile->f_path.dentry;
       	par_out = outfile->f_path.dentry->d_parent->d_inode;
        out_dentry = outfile->f_path.dentry;
        len = vfs_rename(par_tmp,tmp_dentry, par_out, out_dentry, NULL, 0);
                if(len < 0)                           // if rename fails delete the tmpfile
                {
                    ret = -ECANCELED  ;
                        len = vfs_unlink(par_tmp, tmp_dentry,NULL);
                }

    }


    close_out_tmpfile:
        if(out_tmpfile) filp_close(out_tmpfile,NULL);
    close_out_file:
        if(outfile) filp_close(outfile,NULL);
    close_inp_file:
        if(infile)  filp_close(infile,NULL);
    out_err:
        printk("Copying Final Args\n");
	rjob->return_value = ret;
    	rjob->return_buf = NULL;
	return;


}


void perform_checksum(struct job_checksum *kchecksum, struct job_result *rjob, int is_atomic)
{
	
	int ret = 0;
	int  bytes = PAGE_SIZE ;
	mm_segment_t oldfs;
	struct scatterlist sg;
        struct crypto_hash *tfm;
        struct hash_desc desc;
	char *userkey = kmalloc(kchecksum->algo_len*2, GFP_KERNEL);
	char *tmpkey = kmalloc(9, GFP_KERNEL);
	char digest[kchecksum->algo_len] ;
	struct file *inf;
        char *src = (char*)kmalloc(PAGE_SIZE+1, GFP_KERNEL);
	if(IS_ERR(src))
	{
		rjob->return_buf = NULL;
		ret = -ENOMEM;
		goto out_exit;
	}

	//check validity of file
	//open infile
	inf = file_open((const char *)kchecksum->ipFile,O_RDONLY, 0);
	if (!inf || IS_ERR(inf)){
                ret =  (int) PTR_ERR(inf);
                rjob->return_buf = NULL;
		goto out_exit;
        }
//	printk("after file open %d\n", ret);	
	//check if infile is pointer to file
	ret = file_isfile(inf);
	if(ret < 0)
	{
		rjob->return_buf = NULL;
		goto out_closein;
	}
	//check if file id readable
	ret = file_readable(inf);
	if(ret < 0)
	{
		rjob->return_buf = NULL;
		goto out_closein;	
	}
	
	//onvert alg to uppercase and see CRYPTO_ALG_ASYNC	
        tfm = crypto_alloc_hash(kchecksum->hash_algo,0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm))
	{
		ret = (int)PTR_ERR(tfm);
		rjob->return_buf = NULL;
		goto out_closein;
	}

	desc.tfm = tfm;
	crypto_hash_init(&desc);

	
	memset(digest, 0, kchecksum->algo_len);
	inf->f_pos = 0;		/* start offset */
    	oldfs = get_fs();
    	set_fs(KERNEL_DS);
	while( bytes == PAGE_SIZE)
	{
		///printk("inside while\n");
		bytes = inf->f_op->read(inf, src, PAGE_SIZE, &inf->f_pos);
		//printk("no of bytes read %d\n", bytes);
		printk("is atmoic %d\n", is_atomic);
		if(IS_ERR(ERR_PTR(bytes)))
		{
			printk("inside if\n");
			ret = -EINTR;
			if(is_atomic)
			{
				rjob->return_buf = NULL;
				goto out_freedigest;
			}
			else
				goto out_final;
		}
		//printk("before null terminating\n");
		//last iteration - include padding
		*(src + bytes) = '\0';
		//printk("before sg init one src : %s\n", src);
		sg_init_one(&sg , src, bytes);
	//	printk("before crypto hash update \n");
		crypto_hash_update(&desc, &sg, bytes);
	//	printk("after \n");
	}
	
out_final:

	crypto_hash_final(&desc, digest);
	printk("after final\n");
	//copy to user checksum	
	
	*(tmpkey+8) = '\0';
	if(ret >= 0)
	{	int i;
		for ( i = 0; i < kchecksum->algo_len; i++)
		{
			sprintf(tmpkey, "%02x", digest[i]);
			printk("temp %s\n", tmpkey);
			printk("temp len %d\n", strlen(tmpkey));
			strncpy((userkey + i*2), (tmpkey + strlen(tmpkey)-2), 2);
		}
	}
	rjob->return_buf = (char*)kmalloc(kchecksum->algo_len*2 + 1, GFP_KERNEL);
        memcpy(rjob->return_buf, userkey, strlen(userkey));
	*(rjob->return_buf + kchecksum->algo_len*2) = '\0';

	printk("userkey %s\n", rjob->return_buf);
out_freedigest:
	set_fs(oldfs);	
//out_freehash:
	crypto_free_hash(tfm);	
out_closein:
	filp_close(inf,NULL);
out_exit:
	kfree(src);
	kfree(tmpkey);
	kfree(userkey);
	rjob->return_value = ret;
	return;
}
#endif

