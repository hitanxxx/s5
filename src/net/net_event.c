#include "common.h"
#include "net_event.h"
#include "net_event_timer.h"
#include "net_ssl.h"

#define EV_MAP_MAX  (NET_EV_MAX * 2)

typedef int (*net_event_ops_init)(void);
typedef int (*net_event_ops_deinit)(void);
typedef int (*net_event_ops_opt)(ev_t *event, int fd, uint32_t new_events);
typedef int (*net_event_ops_runloop)(uint64_t ms);

typedef struct  {
    net_event_ops_init  init;
    net_event_ops_deinit   end;
    net_event_ops_opt   opt;
    net_event_ops_runloop  loop;
} net_event_ops_t;


typedef struct {
    uint32_t evn;       ///total event number
    queue_t evqueue;    ///total event queue
    
#if defined(EVENT_EPOLL)
    int epfd;
    struct epoll_event *epev;
#else
    fd_set rfds;
    fd_set wfds;
#endif
} g_event_t;

static g_event_t *g_event_ctx = NULL;
static net_event_ops_t g_event_ops = {NULL, NULL, NULL, NULL};


#if defined(EVENT_EPOLL)
static int ev_epoll_init() {
    g_event_ctx->epev = mem_alloc(sizeof(struct epoll_event) * NET_EV_MAX);
    schk(g_event_ctx->epev, return ERROR);

    g_event_ctx->epfd = epoll_create1(0);
    schk(g_event_ctx->epfd >= 0, return ERROR);
    return 0;
}

static int ev_epoll_end() {
    if (g_event_ctx->epfd)
        close(g_event_ctx->epfd);

    if (g_event_ctx->epev)
        mem_free(g_event_ctx->epev);
    return 0;
}

static int ev_epoll_opt(ev_t *event, int fd, uint32_t new_mask) {
    /// want type not same as record type
    if (event->mask != new_mask) {
        if (new_mask == EV_NONE) {
            if (-1 == epoll_ctl(g_event_ctx->epfd, EPOLL_CTL_DEL, fd, NULL)) {
                if (errno == ENOENT) {
                   event->mask = EV_NONE;
                } else {
                    err("ev. epoll_ctl err. [%d] [%s]\n", errno, strerror(errno));
                    return ERROR;
                }
            }
        } else {
            struct epoll_event evsys;
            memset(&evsys, 0, sizeof(struct epoll_event));
            evsys.data.ptr = (void *)event;
            evsys.events = EPOLLET;
            if (new_mask & EV_R)  evsys.events |= EPOLLIN;
            if (new_mask & EV_W)  evsys.events |= EPOLLOUT;
            if (-1 == epoll_ctl(g_event_ctx->epfd, (event->mask == EV_NONE ? EPOLL_CTL_ADD : EPOLL_CTL_MOD), fd, &evsys)) {
                if (errno == EEXIST) {
                    event->mask = new_mask;
                } else {
                    err("ev. epoll_ctl err. [%d] [%s]\n",  errno, strerror(errno));
                    return ERROR;
                }
            }
        }
        event->mask = new_mask;
    }
    return OK;
}

static int ev_epoll_loop(uint64_t ms) {
    int all = epoll_wait(g_event_ctx->epfd, g_event_ctx->epev, NET_EV_MAX, (int)ms);
    if (all <= 0) {
        if (all == 0) {
            return (ms == -1) ? ERROR : AGAIN;
        }
        if (errno == EINTR) {
            err("ev. epoll_wait irq by [syscall]\n");
            return OK;
        }
        err("ev. epoll_wait irq by [err], [%d] [%s]", errno, strerror(errno));
        return ERROR;
    }

    for (int i = 0; i < all; i++) {
        ev_t *ev = g_event_ctx->epev[i].data.ptr;
        uint32_t revents = g_event_ctx->epev[i].events;
        ev->fread = ev->fwrite  = 0;
        
        if (revents & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
            ev->fread = 1;
        }
        if (revents & (EPOLLOUT | EPOLLHUP | EPOLLERR)) {
            ev->fwrite = 1;
        }

        if (ev->fread) {
            ev->fread = 0;
            if (ev->data) {
                con_t *c = (con_t*)ev->data;
                if (!c->fclosing && c->read_cb) {
                    c->read_cb(c);
                }
            }
        } 
        if (ev->fwrite) {
            ev->fwrite = 0;
            if (ev->data) {
                con_t *c = (con_t*) ev->data;
                if (!c->fclosing && c->write_cb) {
                    c->write_cb(c);
                }
            }
        }
    }
    return OK;
}
#else
static int ev_select_init(void) {
    FD_ZERO(&g_event_ctx->rfds);
    FD_ZERO(&g_event_ctx->wfds);
    return OK;
}

static int ev_select_end(void) {
    FD_ZERO(&g_event_ctx->rfds);
    FD_ZERO(&g_event_ctx->wfds);
    return OK;
}

static int ev_select_opt(ev_t *event, int fd, uint32_t new_mask) {
    if (event->mask != new_mask) {
        if (!(new_mask & EV_R) && (event->mask & EV_R))
            FD_CLR(fd, &g_event_ctx->rfds);
        if (!(new_mask & EV_W) && (event->mask & EV_W)) 
            FD_CLR(fd, &g_event_ctx->wfds);
        ///if (!(new_mask & EV_CONNECT) && (event->mask & EV_CONNECT))
        ///    FD_LCR(fd, &g_event_ctx->exceptfds);

        if ((new_mask & EV_R) && !(event->mask & EV_R))
            FD_SET(fd, &g_event_ctx->rfds);
        if ((new_mask & EV_W) && !(event->mask & EV_W))
            FD_SET(fd, &g_event_ctx->wfds);
        ///if ((new_mask & EV_CONNECT) && !(event->mask & EV_CONNECT))
        ///    FD_SET(fd, &g_event_ctx->exceptfds);

        event->mask = new_mask;
    }
    return OK;
}

static int ev_select_loop(uint64_t ms) {
    int fdmax = 0;
    ev_t *ev = NULL;
    queue_t *q = NULL;
    queue_t *n = NULL;

    fd_set rfds = {0};
    fd_set wfds = {0};

    struct timeval tm = {0};
    tm.tv_sec = (time_t)ms / 1000;
    tm.tv_usec = (suseconds_t)((ms % 1000) * 1000);

    if (!queue_empty(&g_event_ctx->evqueue)) {
        /// find max fd in event queue
        q = queue_head(&g_event_ctx->evqueue);
        while (q != queue_tail(&g_event_ctx->evqueue)) {
            n = queue_next(q);
            
            ev = ptr_get_struct(q, ev_t, queue);
            
                con_t *c = ev->data;
            if (c && c->fd > fdmax) fdmax = c->fd;
            
            q = n;
        }
    }

    memcpy(&rfds, &g_event_ctx->rfds, sizeof(fd_set)); /// select return will be change read fds and write fds
    memcpy(&wfds, &g_event_ctx->wfds, sizeof(fd_set));
    int actall = select(fdmax + 1, &rfds, &wfds, NULL, &tm);
    if (actall <= 0) {
        if (actall == 0) {
            return AGAIN;
        }
        if (errno == EINTR) {
            err("ev. select irq by [syscall]\n");
            return OK;
        }
        err("ev. select irq by [err], [%d] [%s]\n", errno, strerror(errno));
        return ERROR;
    }
    int processed = 0;
    q = queue_head(&g_event_ctx->evqueue);
    while (q != queue_tail(&g_event_ctx->evqueue) && processed < actall) {
        ev = ptr_get_struct(q, ev_t, queue);

        if (ev->data) {
            con_t *c= ev->data;
            if (FD_ISSET(c->fd, &rfds)) {
                processed ++;
                ev->fread = 1;
            }
            if (FD_ISSET(c->fd, &wfds)) {
                processed ++;
                ev->fwrite = 1;
            }
        }
        
        if (ev->fread) {
            ev->fread = 0;
            if (ev->data) {
                con_t *c = (con_t*)ev->data;
                if (!c->fclosing && c->read_cb) {
                    c->read_cb(c);
                }
            }
        } 
        if (ev->fwrite) {
            ev->fwrite = 0;
            if (ev->data) {
                con_t *c = (con_t*) ev->data;
                if (!c->fclosing && c->write_cb) {
                    c->write_cb(c);
                }
            }
        }
        
        q = queue_next(q);
    }
    return OK;
}
#endif


int ev_opt(ev_t *event, int fd, uint32_t new_mask) {
    return (g_event_ops.opt ? g_event_ops.opt(event, fd, new_mask) : 0);
}

int ev_loop(void) {
    if (g_event_ops.loop) g_event_ops.loop(ev_timer_remaining());
    systime_update();
    return OK;
}

int ev_alloc(ev_t **ev) {
    if (g_event_ctx->evn < NET_EV_MAX) {
        ev_t *alloc_ev = mem_alloc(sizeof(ev_t));
        schk(alloc_ev, return -1);
        queue_insert_tail(&g_event_ctx->evqueue, &alloc_ev->queue);
        g_event_ctx->evn ++;
        *ev = alloc_ev;
        return OK;
    } 
    err("ev number limit\n");
    return ERROR;
}

int ev_free(ev_t *ev) {
    if (ev) {
        ev->fread = ev->fwrite = 0;
        queue_remove(&ev->queue);
        g_event_ctx->evn --;
        mem_free(ev);
    }
    return OK;
}

int ev_init(void) {
    g_event_ctx = mem_alloc(sizeof(g_event_t));
    schk(g_event_ctx, return ERROR);
    
#if defined(EVENT_EPOLL)
    g_event_ops.init    = ev_epoll_init;
    g_event_ops.end     = ev_epoll_end;
    g_event_ops.opt     = ev_epoll_opt;
    g_event_ops.loop    = ev_epoll_loop;
#else
    g_event_ops.init    = ev_select_init;
    g_event_ops.end     = ev_select_end;
    g_event_ops.opt     = ev_select_opt;
    g_event_ops.loop    = ev_select_loop;
#endif
    
    queue_init(&g_event_ctx->evqueue);
    if (g_event_ops.init) g_event_ops.init();
    
    return OK;
}

int ev_exit(void) {
    if (g_event_ctx) {
        if (g_event_ops.end) g_event_ops.end();
        mem_free(g_event_ctx);
        g_event_ctx = NULL;
    }
    
    return OK;
}

