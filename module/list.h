#ifndef INTERNAL_LIST_H
#define INTERNAL_LIST_H

/*
 * Header for kernel space
 */

struct list_head {
    struct list_head* prev;
    struct list_head* next;
};

static inline void INIT_LIST_HEAD(struct list_head* head)
{
    head->next = head;
    head->prev = head;
}

static inline int list_empty(const struct list_head* head)
{
    return (head->next == head);
}

static inline void list_add_tail(struct list_head* node, struct list_head* head)
{
    struct list_head* prev = head->prev;

    prev->next = node;
    node->next = head;
    node->prev = prev;
    head->prev = node;
}

static inline void list_del(struct list_head* node)
{
    struct list_head* next = node->next;
    struct list_head* prev = node->prev;

    next->prev = prev;
    prev->next = next;
}

#endif