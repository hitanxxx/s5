#include "common.h"

int ezac_node_free(ezac_node_t *root) {
    ezac_node_t *stack[4096] = {0};
    int stackn = 0;
    int i = 0;

    stack[stackn++] = root;
    while (stackn > 0) {
        ezac_node_t *p = stack[--stackn];
        for (i = 0; i < EZAC_MAX; i++) {
            if (p->arr[i])
                stack[stackn++] = p->arr[i];
        }
        if (p != root)
            sys_free(p);
    }
    return OK;
}

int ezac_free(ezac_ctx_t *ctx) {
    if (ctx) {
        ezac_node_free(&ctx->root);
        sys_free(ctx);
    }
    return OK;
}

ezac_ctx_t *ezac_init() {
    ezac_ctx_t *ctx = NULL;
    schk(ctx = sys_alloc(sizeof(ezac_ctx_t)), return NULL);
    ctx->root.pfail = &ctx->root;
    ctx->cur = &ctx->root;
    return ctx;
}

int ezac_add(ezac_ctx_t *ctx, char *data, int datan) {
    ezac_node_t *n = &ctx->root;
    int i = 0;

    for (i = 0; i < datan; i++) {
        int idx = data[i];
        if (idx < 0 || idx > EZAC_MAX)
            idx = 0;
        if (!n->arr[idx]) {
            schk(n->arr[idx] = sys_alloc(sizeof(ezac_node_t)), return -1);
        }
        n = n->arr[idx];
    }
    n->fendup = 1;
    return OK;
}

int ezac_compiler(ezac_ctx_t *ctx) {
    ezac_node_t *stack[4096] = {0};
    int stackn = 0;
    int i = 0;

    for (i = 0; i < EZAC_MAX; i++) {
        if (ctx->root.arr[i]) {
            ctx->root.arr[i]->pfail = &ctx->root;
            stack[stackn++] = ctx->root.arr[i];
        }
    }

    while (stackn > 0) {
        ezac_node_t *n = stack[--stackn];
        for (i = 0; i < EZAC_MAX; i++) {
            if (n->arr[i]) {
                ezac_node_t *x = n->pfail;
                char find = 0;
                do {
                    if (x->arr[i]) {
                        find = 1;
                        break;
                    }
                    x = x->pfail;
                } while (x != &ctx->root);
                n->arr[i]->pfail = (find ? x->arr[i] : x);
                stack[stackn++] = n->arr[i];
            }
        }
    }
    return OK;
}

int ezac_reset(ezac_ctx_t *ctx) {
    ctx->cur = &ctx->root;
    return OK;
}

int ezac_find(ezac_ctx_t *ctx, char *data, int datan) {
    for (int i = 0; i < datan; i++) {
        int idx = data[i];
        if (idx < 0 || idx > EZAC_MAX)
            idx = 0;
        if (!ctx->cur->arr[idx])
            ctx->cur = ctx->cur->pfail;

        if (ctx->cur->arr[idx]) {
            if (ctx->cur->arr[idx]->fendup) {
                ezac_reset(ctx);
                return OK;
            } else {
                ctx->cur = ctx->cur->arr[idx];
            }
        }
    }
    return ERROR;
}
