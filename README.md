```markdown
# MEM30-C. Do not access freed memory

Evaluating a pointer—including dereferencing the pointer, using it as an operand of an arithmetic operation, type casting it, and using it as the right-hand side of an assignment—into memory that has been deallocated by a memory management function is undefined behavior. Pointers to memory that has been deallocated are called dangling pointers. Accessing a dangling pointer can result in exploitable vulnerabilities.

According to the C Standard, using the value of a pointer that refers to space deallocated by a call to the `free()` or `realloc()` function is undefined behavior. (See [undefined behavior 177](#)). 

Reading a pointer to deallocated memory is undefined behavior because the pointer value is indeterminate and might be a trap representation. Fetching a trap representation might perform a hardware trap (but is not required to).

It is at the memory manager's discretion when to reallocate or recycle the freed memory. When memory is freed, all pointers into it become invalid, and its contents might either be returned to the operating system, making the freed space inaccessible, or remain intact and accessible. As a result, the data at the freed location can appear to be valid but change unexpectedly. Consequently, memory must not be written to or read from once it is freed.

## Noncompliant Code Example

This example from Brian Kernighan and Dennis Ritchie [Kernighan 1988] shows both the incorrect and correct techniques for freeing the memory associated with a linked list. In their (intentionally) incorrect example, `p` is freed before `p->next` is executed, so that `p->next` reads memory that has already been freed.

```c
#include <stdlib.h>
  
struct node {
  int value;
  struct node *next;
};
  
void free_list(struct node *head) {
  for (struct node *p = head; p != NULL; p = p->next) {
    free(p);
  }
}
```

## Compliant Solution

Kernighan and Ritchie correct this error by storing a reference to `p->next` in `q` before freeing `p`:

```c
#include <stdlib.h>
  
struct node {
  int value;
  struct node *next;
};
  
void free_list(struct node *head) {
  struct node *q;
  for (struct node *p = head; p != NULL; p = q) {
    q = p->next;
    free(p);
  }
}
```

## Noncompliant Code Example

In this noncompliant code example, `buf` is written to after it has been freed. Write-after-free vulnerabilities can be exploited to run arbitrary code with the permissions of the vulnerable process. Typically, allocations and frees are far removed, making it difficult to recognize and diagnose these problems.

```c
#include <stdlib.h>
#include <string.h>
 
int main(int argc, char *argv[]) {
  char *return_val = 0;
  const size_t bufsize = strlen(argv[0]) + 1;
  char *buf = (char *)malloc(bufsize);
  if (!buf) {
    return EXIT_FAILURE;
  }
  /* ... */
  free(buf);
  /* ... */
  strcpy(buf, argv[0]);
  /* ... */
  return EXIT_SUCCESS;
}
```

## Compliant Solution

In this compliant solution, the memory is freed after its final use:

```c
#include <stdlib.h>
#include <string.h>
 
int main(int argc, char *argv[]) {
  char *return_val = 0;
  const size_t bufsize = strlen(argv[0]) + 1;
  char *buf = (char *)malloc(bufsize);
  if (!buf) {
    return EXIT_FAILURE;
  }
  /* ... */
  strcpy(buf, argv[0]);
  /* ... */
  free(buf);
  return EXIT_SUCCESS;
}
```

## Noncompliant Code Example

In this noncompliant example, `realloc()` may free `c_str1` when it returns a null pointer, resulting in `c_str1` being freed twice. The C Standards Committee's proposed response to Defect Report #400 makes it implementation-defined whether or not the old object is deallocated when size is zero and memory for the new object is not allocated. The current implementation of `realloc()` in the GNU C Library and Microsoft Visual Studio's Runtime Library will free `c_str1` and return a null pointer for zero byte allocations. Freeing a pointer twice can result in a potentially exploitable vulnerability commonly referred to as a double-free vulnerability [Seacord 2013b].

```c
#include <stdlib.h>
  
void f(char *c_str1, size_t size) {
  char *c_str2 = (char *)realloc(c_str1, size);
  if (c_str2 == NULL) {
    free(c_str1);
  }
}
```

## Compliant Solution

This compliant solution does not pass a size argument of zero to the `realloc()` function, eliminating the possibility of `c_str1` being freed twice:

```c
#include <stdlib.h>
  
void f(char *c_str1, size_t size) {
  if (size != 0) {
    char *c_str2 = (char *)realloc(c_str1, size);
    if (c_str2 == NULL) {
      free(c_str1);
    }
  }
  else {
    free(c_str1);
  }
}
```

If the intent of calling `f()` is to reduce the size of the object, then doing nothing when the size is zero would be unexpected; instead, this compliant solution frees the object.

## Noncompliant Code Example

In this noncompliant example (CVE-2009-1364) from libwmf version 0.2.8.4, the return value of `gdRealloc` (a simple wrapper around `realloc()` that reallocates space pointed to by `im->clip->list`) is set to `more`. However, the value of `im->clip->list` is used directly afterwards in the code, and the C Standard specifies that if `realloc()` moves the area pointed to, then the original block is freed. An attacker can then execute arbitrary code by forcing a reallocation (with a sufficient `im->clip->count`) and accessing freed memory [xorl 2009].

```c
void gdClipSetAdd(gdImagePtr im, gdClipRectanglePtr rect) {
  gdClipRectanglePtr more;
  if (im->clip == 0) {
   /* ... */
  }
  if (im->clip->count == im->clip->max) {
    more = gdRealloc (im->clip->list,(im->clip->max + 8) *
                      sizeof (gdClipRectangle));
    /*
     * If the realloc fails, then we have not lost the
     * im->clip->list value.
     */
    if (more == 0) return;
    im->clip->max += 8;
  }
  im->clip->list[im->clip->count] = *rect;
  im->clip->count++;
 
}
```

## Compliant Solution

This compliant solution simply reassigns `im->clip->list` to the value of `more` after the call to `realloc()`:

```c
void
