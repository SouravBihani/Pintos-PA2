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
static int fid_val = 2;

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
  list_init(&file_list);
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
            f->eax = sys_create(*(p+1), *(p+2));
            break;

          case SYS_OPEN:
            f->eax = sys_open(*(p+1));
	    break;

	  case SYS_SEEK:
            f->eax = sys_seek(*(p+1), *(p+2));
	    break;

	  case SYS_FILESIZE:
            f->eax = sys_filesize(*(p+1));
	    break;

	  case SYS_TELL:
            f->eax = sys_tell(*(p+1));
	    break;

	  case SYS_READ:
            f->eax = sys_read(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_WRITE:
            f->eax = sys_write(*(p+1), *(p+2), *(p+3));
	    break;

	  case SYS_EXEC:
            f->eax = sys_exec(*(p+1));
	    break;

	  case SYS_WAIT:
            f->eax = sys_wait(*(p+1));
	    break;

	  case SYS_REMOVE:
            f->eax = sys_remove(*(p+1));
	    break;

	  case SYS_CLOSE:
            f->eax = sys_close(*(p+1));
	    break;

	  case SYS_EXIT:
            f->eax = sys_exit(*(p+1));
	    break;
        }
      return;
    }
  }
  
  sys_exit(-1);
  ///Customized
}

//Customized
int
sys_write(int fd, const void *buffer, unsigned length)
{
  if(fd == STDOUT_FILENO)
    putbuf(buffer, length);
  else if(fd == STDIN_FILENO)
    return -1;
  else if(!is_user_vaddr(buffer) || !is_user_vaddr(buffer+length))
    sys_exit(-1);
  else
  {
    struct file * file = find_file_by_fd(fd);
    if(file)
      return file_write(file, buffer, length);
  }
    
  return -1;
}

int
sys_exit(int status)
{
  struct thread *thr = thread_current();
  while(!list_empty(&thr->files))
    sys_close(list_entry(list_begin(&thr->files), struct fd_elem, thread_elem)->fd);
  
  thr->ret_status = status;
  thread_exit();
  return -1;
}

int
sys_create(const char *file, unsigned initial_size)
{
  if(file)
    return filesys_create(file, initial_size);
  return sys_exit(-1);
}

int
sys_open(const char *file)
{
  if(!file)
    return -1;
  if(!is_user_vaddr(file))
    sys_exit(-1);
  struct file *file1 = filesys_open(file);
  if(!file1)
    return -1;
    
  struct fd_elem *fde = (struct fd_elem *)malloc(sizeof(struct fd_elem));
  if(!fde)
  {
    file_close(file1);
    return -1;
  }
    
  fde->file = file1;
  fde->fd = fid_val++;
  list_push_back(&file_list, &fde->elem);
  list_push_back(&thread_current()->files, &fde->thread_elem);

  return fde->fd;
}

int
sys_close(int fd)
{
  struct fd_elem *file = find_fd_elem_by_fd_in_process(fd);
  
  if(file)
  {
    file_close(file->file);
    list_remove(&file->elem);
    list_remove(&file->thread_elem);
    free(file);
  }

  return 0;
}

int
sys_read(int fd, void *buffer, unsigned size)
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
  return process_execute(cmd);
}

int
sys_wait(int pid)
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

int
sys_filesize(int fd)
{
  struct file *file = find_file_by_fd(fd);
  if(file)
    return file_length(file);
  return -1;
}

int
sys_tell(int fd)
{
  struct file *file = find_file_by_fd(fd);
  if(file)
    return file_tell(file);
  return -1;
}

int
sys_seek(int fd, unsigned pos)
{
  struct file *file = find_file_by_fd(fd);
  if(!file)
    return -1;
  file_seek(file, pos);
  return 0;
}

int
sys_remove(const char *file)
{
  if(!is_user_vaddr(file))
    sys_exit(-1);
    
  return filesys_remove(file);
}

struct file *
find_file_by_fd(int fd)
{
  struct fd_elem *ret = find_fd_elem_by_fd(fd);
  if(!ret)
    return NULL;
  return ret->file;
}

struct fd_elem *
find_fd_elem_by_fd(int fd)
{
  struct list_elem *l;
  struct fd_elem *ret;
  
  for(l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
  { 
    ret = list_entry(l, struct fd_elem, elem);
    if(ret->fd == fd)
      return ret;
  } 
  return NULL;
}
struct fd_elem *
find_fd_elem_by_fd_in_process(int fd)
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
