#include <stdio.h>
#include <stdlib.h>

#include "list.h"


typedef struct _myitem {
  struct list_head head;
  int i;
} myitem;

LIST_HEAD(mylist);

void main(void)
{
  int i;
  struct list_head *pos, *pos2;
  

  for (i=0; i < 10; i++) {
    myitem *mi = malloc(sizeof(myitem));

    mi->i = i;
    list_add_tail(&mi->head, &mylist);
  }

  list_for_each_safe(pos, pos2, &mylist) {
    printf("%d\n", ((myitem *)pos)->i);
    if (((myitem *)pos)->i == 3)
      list_del(pos);
  }

  list_for_each_safe(pos, pos2, &mylist) {
    printf("%d\n", ((myitem *)pos)->i);

  }

}
