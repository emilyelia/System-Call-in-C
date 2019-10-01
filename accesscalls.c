#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include "securitycalls.h"
#include<linux/module.h>
#include<linux/proc_fs.h>
#include<linux/cred.h>

asmlinkage long sys_set_security_level(int pid, int new_level) {
    struct task_struct *task = current;
    int userid = task->cred->uid.val;
    long newlevel = (long)new_level;
    struct task_struct *proces;
	int userlevel = task->securitylevel;
    struct task_struct *proces1;
    
    //if userid = 0 then the process is sudo and it can do whatever it wants
    if (userid == 0) 
	{
        for_each_process(proces)
		{
            if (proces->pid == pid) 
			{
                proces->securitylevel = new_level;
                return newlevel;
            }
        }
    }
    //else it is a user level process in which case we must check for the parameter cases
	//lets try checking for the specific cases in which we CAN change the seclvl
	//1) a user process can write the sec lvl of a process if the process is at a lower level
	//2) a user process can only raise the level of a process to its own level
	//3) a user process can lower its own security level
	//4) a user process cannot lower the security level of a different process with the same level.
    for_each_process(proces1) 
	{
        if (proces1->pid == pid) //we found the process we want to change
		{
            if (userlevel == proces1->securitylevel && task->pid != proces1->pid) 	//4) and 3) 
			{
                return -1;
            }
            if (userlevel >= new_level) //user process is able to edit in this case assuming it passed cases 3 and 4.
			{
                proces1->securitylevel = newlevel;
                return newlevel;
            }
            
        }
    }
    return -1;	//otherwise we are returning -1 because it is not possible to change seclvl.
}

asmlinkage long sys_get_security_level(int pid)
{
	//invoke syscall to read the securitylevel of the process and return it
	struct task_struct *proces;
	for_each_process(proces)
	{
		if(proces->pid == pid)
		{
			return (proces->securitylevel);
		}
	}
	return -1;

}