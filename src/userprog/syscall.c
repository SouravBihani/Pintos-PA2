#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

//Customized
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
///Customized

static void syscall_handler (struct intr_frame *f);

//Customized
struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
  struct list_elem thread_elem;
};
///Customized

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  //Customized
  syscall_vec[SYS_EXIT] = (handler)sys_exit;
  //syscall_vec[SYS_CREATE] = (handler)sys_create;
  //syscall_vec[SYS_OPEN] = (handler)sys_open;
  //syscall_vec[SYS_CLOSE] = (handler)sys_close;
  //syscall_vec[SYS_READ] = (handler)sys_read;
  syscall_vec[SYS_WRITE] = (handler)sys_write;
  syscall_vec[SYS_EXEC] = (handler)sys_exec;
  syscall_vec[SYS_WAIT] = (handler)sys_wait;
  //syscall_vec[SYS_FILESIZE] = (handler)sys_filesize;
  //syscall_vec[SYS_SEEK] = (handler)sys_seek;
  //syscall_vec[SYS_TELL] = (handler)sys_tell;
  //syscall_vec[SYS_REMOVE] = (handler)sys_remove;
  
  list_init (&file_list);
  ///Customized
}

static void
syscall_handler (struct intr_frame *f) 
{
  //Customized
  int *p = f->esp;
  
  if (is_user_vaddr(p) && !(*p < SYS_HALT || *p > SYS_INUMBER)) {
    if (is_user_vaddr(p+1) && is_user_vaddr(p+2) && is_user_vaddr(p+3)) {
	switch(*p)
        {
          case SYS_CREATE:
            //f->eax = (handler)sys_create(*(p+1), *(p+2), *(p+3));
            break;

          case SYS_OPEN:
            //f->eax = (handler)sys_open(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_SEEK:
            //f->eax = (handler)sys_seek(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_FILESIZE:
            //f->eax = (handler)sys_filesize(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_TELL:
            //f->eax = (handler)sys_tell(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_READ:
            f->eax = (handler)sys_read(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_WRITE:
            f->eax = (handler)sys_write(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_EXEC:
            //f->eax = (handler)sys_exec(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_WAIT:
            //f->eax = (handler)sys_wait(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_REMOVE:
            //f->eax = (handler)sys_remove(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_CLOSE:
            //f->eax = (handler)sys_close(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_EXIT:
            //f->eax = (handler)sys_exit(*(p+1), *(p+2), *(p+3));
	    break;
        }      
	//f->eax = syscall_vec[*p] (*(p+1), *(p+2), *(p+3));
      return;
    }
  }
  
  sys_exit(-1);
  ///Customized
}

//Customized
int
sys_write (int fd, const void *buffer, unsigned length)
{
  int ret = -1;

  if (fd == STDOUT_FILENO)
    putbuf (buffer, length);
  else if (fd == STDIN_FILENO)
    return ret;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    sys_exit (-1);
  else
  {
    struct file * f = find_file_by_fd (fd);
    if (f)
      ret = file_write (f, buffer, length);
  }
    
  return ret;
}

int
sys_exit (int status)
{
  struct thread *t = thread_current ();
  while (!list_empty (&t->files))
    sys_close (list_entry (list_begin (&t->files), struct fd_elem, thread_elem)->fd);
  
  t->ret_status = status;
  thread_exit ();
  return -1;
}

int
sys_create (const char *file, unsigned initial_size)
{
  if (!file)
    return sys_exit (-1);
  return filesys_create (file, initial_size);
}

int
sys_open (const char *file)
{
  int ret = -1;
  if (!file)
    return ret;
  if (!is_user_vaddr (file))
    sys_exit (-1);
  struct file *f = filesys_open (file);
  if (!f)
    return ret;
    
  struct fd_elem *fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
  if (!fde)
  {
    file_close (f);
    return ret;
  }
    
  fde->file = f;
  fde->fd = alloc_fid ();
  list_push_back (&file_list, &fde->elem);
  list_push_back (&thread_current ()->files, &fde->thread_elem);
  ret = fde->fd;

  return ret;
}

int
sys_close(int fd)
{
  struct fd_elem *f = find_fd_elem_by_fd_in_process (fd);
  
  if (f)
  {
    file_close (f->file);
    list_remove (&f->elem);
    list_remove (&f->thread_elem);
    free (f);
  }

  return 0;
}

int
sys_read (int fd, void *buffer, unsigned size)
{
  int ret = -1;
  
  if(fd == STDOUT_FILENO)
    return ret;
  else if(!is_user_vaddr(buffer) || !is_user_vaddr(buffer+size))
    sys_exit(-1);
  else
  {
    struct file *file = find_file_by_fd(fd);
    if(file)
      ret = file_read(file, buffer, size);
  }
    
  return ret;
}

int
sys_exec(const char *cmd)
{
  if (!cmd || !is_user_vaddr(cmd))
    return -1;
  
  return process_execute(cmd);
}

int
sys_wait(pid_t pid)
{
  int ret = -1;

  struct thread *thr = get_thread_by_tid(pid);
  if(thr->ret_status == 0xdcdcdcdc)
    return ret;
  if(thr->ret_status != 0xcdcdcdcd && thr->ret_status != 0xdcdcdcdc)
    return thr->ret_status;

  sema_down(&thr->wait);
  ret = thr->ret_status;
  printf("%s: exit(%d)\n", thr->name, thr->ret_status);
  while(thr->status == THREAD_BLOCKED)
    thread_unblock(thr);
  
  thr->ret_status = 0xdcdcdcdc;
  return ret;
}

struct file *
find_file_by_fd (int fd)
{
  struct fd_elem *ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

struct fd_elem *
find_fd_elem_by_fd (int fd)
{
  struct list_elem *l;
  struct fd_elem *ret;
  
  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
  { 
    ret = list_entry (l, struct fd_elem, elem);
    if (ret->fd == fd)
      return ret;
  } 
  return NULL;
}

int
alloc_fid (void)
{
  static int fid = 2;
  return fid++;
}

int
sys_filesize (int fd)
{
  struct file *f = find_file_by_fd (fd);
  if (!f)
    return -1;
  return file_length (f);
}

int
sys_tell (int fd)
{
  struct file *f = find_file_by_fd (fd);
  if (!f)
    return -1;
  return file_tell (f);
}

int
sys_seek (int fd, unsigned pos)
{
  struct file *f = find_file_by_fd (fd);
  if (!f)
    return -1;
  file_seek (f, pos);
  return 0;
}

int
sys_remove (const char *file)
{
  if (!file)
    return false;
  if (!is_user_vaddr (file))
    sys_exit (-1);
    
  return filesys_remove (file);
}

struct fd_elem *
find_fd_elem_by_fd_in_process (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  struct thread *t = thread_current ();
  
  for (l = list_begin (&t->files); l != list_end (&t->files); l = list_next (l))
  {  
    ret = list_entry (l, struct fd_elem, thread_elem);
    if (ret->fd == fd)
      return ret;
  } 
  return NULL;
}
