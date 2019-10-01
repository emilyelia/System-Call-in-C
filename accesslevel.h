#ifndef ACCESSLEVEL
#define ACCESSLEVEL

int set_access_level(int pid, int new_level);
int get_access_level(int pid);
int* retrieve_set_access_params(int pid, int new_level);
int* retrieve_get_access_params(int pid);
int interpret_set_access_result(int ret_value);
int interpret_get_access_result(int ret_value);

#endif