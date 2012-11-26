#include <stdlib.h>

typedef struct _thing_d {int id; struct _thing_d *next;} Thing;

static Thing *new_node(int id)
{
    Thing *t = malloc(sizeof(Thing));
    t->id = id;
    return t;
}

int main(void)
{
    int i;
    Thing *head, *curr;

    head = curr = NULL;

    for (i=0; i<10; i++)
    {
        curr = new_node(i);
        curr->next = head;
        head = curr;
    }

    return 0;
}
