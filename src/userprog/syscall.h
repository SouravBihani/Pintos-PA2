#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

//Customized
typedef int pid_t;

int sys_exit (int status);
int sys_write (int fd, const void *buffer, unsigned length);
int sys_create (const char *file, unsigned initial_size);
int sys_open (const char *file);
int sys_close (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_exec (const char *cmd);
int sys_wait (pid_t pid);
int sys_filesize (int fd);
int sys_tell (int fd);
int sys_seek (int fd, unsigned pos);
int sys_remove (const char *file);
int alloc_fid (void);

struct file *find_file_by_fd (int fd);
struct fd_elem *find_fd_elem_by_fd (int fd);
struct fd_elem *find_fd_elem_by_fd_in_process (int fd);
struct lock file_lock;  
struct list file_list;

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
handler syscall_vec[128];
///Customized

#endif /* userprog/syscall.h */
