#include "common.h"
#include "net_event.h"
#include "net_event_timer.h"
#include "net_ssl.h"

static heap_t *g_heap = NULL;

static ev_timer_t *ev_timer_minimum(void) {
    heap_node_t *min_node = heap_min(g_heap);
    if (min_node) {
        ev_timer_t *min_timer = ptr_get_struct(min_node, ev_timer_t, node);
        return min_timer;
    }
    return NULL;
}

int ev_timer_del(ev_timer_t *timer) {
    if (timer->f_timeset) {
        schk(heap_del(g_heap, timer->node.index) == 0, return ERROR);
        timer->f_timeset = 0;
    }
    return OK;
}

int ev_timer_add(ev_timer_t *timer, net_timer_cb cb, void *data, uint64_t delay_ms) {
    if (timer->f_timeset) {
        schk(OK == ev_timer_del(timer), return ERROR);
    }

    if (delay_ms == 0) delay_ms = 1;
    timer->cb = cb;
    timer->user_data = data;
    timer->delay_ms = delay_ms;
    timer->node.key = (systime_msec() + delay_ms);
    schk(0 == heap_add(g_heap, &timer->node), return ERROR);
    timer->f_timeset = 1;
    return OK;
}

uint64_t ev_timer_remaining(void) {
    uint64_t timestamp = 0;
    for (;;) {
        ev_timer_t *timer = ev_timer_minimum();
        if (timer) {
            if (timer->node.key > systime_msec()) {
                timestamp = (timer->node.key - systime_msec());
                break;
            } else {
                if (timer->f_once) {
                    ev_timer_del(timer);    ///del timer 
                } else {
                    ev_timer_add(timer, timer->cb, timer->user_data, timer->delay_ms);  ///refresh timer
                }
                if (timer->cb) timer->cb(timer);
            }
        } else {
            timestamp = -1;
            break;
        }
    }
    return timestamp;
}

int ev_timer_init(void) {
    schk(OK == heap_create(&g_heap, NET_EV_MAX * 2), return ERROR);
    return OK;
}

int ev_timer_exit(void) {
    if (g_heap) {
        heap_free(g_heap);
        g_heap = NULL;
    }
    return OK;
}
