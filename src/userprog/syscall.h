#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

//Customized
int sys_write(int fd, const void *buffer, unsigned length);
int sys_create(const char *file, unsigned initial_size);
int sys_open(const char *file);
int sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_exec(const char *cmd);
int sys_wait(int pid);
int sys_filesize(int fd);
int sys_tell(int fd);
int sys_seek(int fd, unsigned pos);
int sys_remove(const char *file);
int sys_exit(int status);

struct file *find_file_by_fd(int fd);
struct fd_elem *find_fd_elem_by_fd(int fd);
struct fd_elem *find_fd_elem_by_fd_in_process(int fd);
struct list file_list;
///Customized

#endif /* userprog/syscall.h */
