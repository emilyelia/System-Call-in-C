#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "accesslevel.h"
#include <stdlib.h>
//library functions

int set_access_level(int pid, int new_level)
{
        //return new_level on success and -1 otherwise
        //syscall(332, PID, newlevel)
        return syscall(335, pid, new_level);
}

int get_access_level(int pid)
{
        //return security level on success, -1 if fails
        return syscall(336, pid);
}




//{ call number, number of parameters, parameter1, parameter2}
int* retrieve_set_access_params (int pid, int new_level)
{
        //return an int array of 2-4 values that can be used to make the set_security_level syscall
        //syscall(332, PID, newlevel) returns a long integer
        int *params = malloc(4);
        params[0] = 335;
        params[1] = 2;
        params[2] = pid;
        params[3] = new_level;
        return params;
}


int* retrieve_get_access_params(int pid)
{
        //return an int array of 2-4 values that can be used to make the get_security_level syscall
        int *params = malloc(3);
        params[0] = 336;
        params[1] = 1;
        params[2] = pid;
        return params;
}


int interpret_set_access_result (int ret_value)
{
        //after making the sys call, pass the return value from the syscall to this function call.
        //This should return set_security_level's interpretation of the sys call completing with return value ret_value
        if(ret_value == -1)
        {
                printf("The security level was not able to be modified.\n");
                return ret_value;
        }
        if(ret_value >= 0)
        {
                printf("The security level was changed to be %d\n.", ret_value);
                return ret_value;
        }
        return -1;

}


int interpret_get_access_result (int ret_value)
{
        //same as above but for get_security_level
        if(ret_value == -1)
        {
                printf("The retrieval of the security level failed.\n");
                return ret_value;
        }
        if(ret_value >= 0)
        {
                printf("The security level is %d\n", ret_value);
                return ret_value;
        }
         return -1;
}



