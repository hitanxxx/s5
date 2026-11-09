#include "common.h"

int heap_create(heap_t **heap, uint32_t size) {
    heap_t *nheap;

    ///index 0 unused. becasue 0*2 = 0, 0*2 + 1 = 0.
    int alloc_size = sizeof(heap_t) + (sizeof(heap_node_t *) * (size + 1));
    schk(nheap = (heap_t *)sys_alloc(alloc_size), return -1);
    nheap->space = size;
    nheap->index = 0;
    nheap->array[0] = NULL;
    *heap = nheap;
    return 0;
}

int heap_free(heap_t *heap) {
    if (heap) {
        sys_free(heap);
    }
    return 0;
}

int heap_add(heap_t *heap, heap_node_t *node) {
    if (!node) {
        err("heap add node empty\n");
        return -1;
    }

    ///oom
    if (heap->index >= heap->space)
        return -1;

    heap->index++;
    uint32_t pos = heap->index;

    while ((pos / 2) > 0 && node->key < heap->array[pos / 2]->key) {
        heap->array[pos] = heap->array[pos / 2];
        heap->array[pos]->index = pos;

        pos = pos / 2;
    }
    heap->array[pos] = node;
    heap->array[pos]->index = pos;
    return 0;
}

int heap_del(heap_t *heap, uint32_t del_index) {
    heap_node_t *tail_node;
    
    if (heap_empty(heap)) {
        err("heap empty\n");
        return -1;
    }
    ///out of space 
    if (del_index > heap->index || del_index == 0) {
        err("heap delindex illegal [%d], heapindex [%d]\n", del_index, heap->index);
        return -1;
    }

    tail_node = heap->array[heap->index];
    heap->index--;

    uint32_t pos = del_index;
    while (pos * 2 <= heap->index) { /// left child is necessary. right child is unnecessary
        uint32_t child_min = pos * 2;
        if ((pos * 2 + 1) <= heap->index) {
            child_min = (heap->array[pos * 2]->key < heap->array[pos * 2 + 1]->key)  ? (pos * 2) : (pos * 2 + 1);
        }

        if (tail_node->key >= heap->array[child_min]->key) {
            heap->array[pos] = heap->array[child_min];
            heap->array[pos]->index = pos;
            pos = child_min;
        } else {
            break;
        }
    }
    heap->array[pos] = tail_node;
    heap->array[pos]->index = pos;
    return 0;
}

int heap_empty(heap_t *heap) {
    if (heap && (heap->space < 1 || heap->index < 1)) {
        return 1;
    }
    return 0;
}

heap_node_t *heap_min(heap_t *heap) {
    if (heap && (heap->index < 1 || heap->space < 1)) {
        return NULL;
    }
    return heap->array[1];
}

int heap_num(heap_t *heap) { 
    if (heap) {
        return heap->index;
    }
    return 0;
}

