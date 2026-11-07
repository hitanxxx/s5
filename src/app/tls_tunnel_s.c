#include "common.h"
#include "dns.h"
#include "tls_tunnel_s.h"
#include "socks5.h"
#include "tls_tunnel_c.h"

#define TLS_TUNNEL_AUTH_FILE_MAX (4 * 1024)

typedef struct {
    ezac_ctx_t *ac;
} tls_tunnel_s_t;
static tls_tunnel_s_t *g_ses_ctx = NULL;

int tls_session_alloc(tls_tunnel_session_t **session) {
    tls_tunnel_session_t *alloc_session = mem_alloc(sizeof(tls_tunnel_session_t));
    if (alloc_session) {
        *session = alloc_session;
        return OK;
    } 
    err("tls tunnel session alloc err\n");
    return ERROR;
}

void tls_session_release_by_cdown(void *data) {
    tls_tunnel_session_t *session = data;

    if (session->s5) {
        s5_free(session->s5);
        session->s5 = NULL;
    }
    dns_resolve_free(&session->dns);
    mem_free(session);
}

void tls_session_release_by_cup(void *data) {
    /// do nothing
    return;
}

void tls_session_timeout(ev_timer_t *timer) {
    con_t *c = ev_timer_userdata(timer);
    tls_tunnel_session_t *session = c->user_data;

    if (session->cup) {
        net_free(session->cup);
    }
    
    if (session->cdown) {
        net_free(session->cdown);
    }
    return;
}

static int tls_tunnel_recv(con_t *c, meta_t *meta) {
    int recv_cnt = 0;
    while (meta_getfree(meta) > 0) {
        int recvn = c->recv(c, meta->last, meta_getfree(meta));
        if (recvn < 0) {
            if (recvn == ERROR) {
                return ERROR;
            } else if (recvn == AGAIN) {
                return AGAIN;
            }
            break;
        }
        meta->last += recvn;
        recv_cnt += recvn;
    }
    return recv_cnt;
}

static int tls_tunnel_send(con_t *c, meta_t *meta) {
    int send_cnt = 0;
    while (meta_getlen(meta) > 0) {
        int sendn = c->send(c, meta->pos, meta_getlen(meta));
        if (sendn < 0) {
            if (sendn == AGAIN) {
                return AGAIN;
            } else if (sendn == ERROR) {
                return ERROR;
            }
        }
        meta->pos += sendn;
        send_cnt += sendn;
    }
    return send_cnt;
}

static int tls_tunnel_down2up_recv_priority(con_t *c) {
    tls_tunnel_session_t *session = c->user_data;
    con_t *cdown = session->cdown;
    con_t *cup = session->cup;
    int ret = 0;

    net_timer_add(cdown, tls_session_timeout, TLS_TMOUT);
    net_timer_add(cup, tls_session_timeout, TLS_TMOUT);

    for (;;) {
        ret = tls_tunnel_recv(cdown, cdown->meta);
        if (ret == ERROR) {
            session->frecv_err_down = 1;
            if (meta_getlen(cdown->meta) < 1) {
                net_free(cup);
                net_free(cdown);
                return ERROR;
            }
        } else if (ret == AGAIN) {
            if (meta_getlen(cdown->meta) < 1) {
                net_ev_clr(cup, EV_W);
                net_ev_add(cdown, EV_R);
                return AGAIN;
            }
        }

        ret = tls_tunnel_send(cup, cdown->meta);
        if (ret == ERROR) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        } else if (ret == AGAIN) {
            net_ev_add(cup, EV_W);
            net_ev_clr(cdown, EV_R);
            return AGAIN;
        }

        if (session->frecv_err_down) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
        meta_clr(cdown->meta);
    }
    return OK;
}

static int tls_tunnel_down2up_send_priority(con_t *c) {
    tls_tunnel_session_t *session = c->user_data;
    con_t *cdown = session->cdown;
    con_t *cup = session->cup;
    int ret = 0;

    net_timer_add(cdown, tls_session_timeout, TLS_TMOUT);
    net_timer_add(cup, tls_session_timeout, TLS_TMOUT);

    for (;;) {
        ret = tls_tunnel_send(cup, cdown->meta);
        if (ret == ERROR) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        } else if (ret == AGAIN) {
            net_ev_add(cup, EV_W);
            net_ev_clr(cdown, EV_R);
            return AGAIN;
        }

        if (session->frecv_err_down) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
        meta_clr(cdown->meta);

        ret = tls_tunnel_recv(cdown, cdown->meta);
        if (ret == ERROR) {
            session->frecv_err_down = 1;
            if (meta_getlen(cdown->meta) < 1) {
                net_free(cup);
                net_free(cdown);
                return ERROR;
            }
        } else if (ret == AGAIN) {
            if (meta_getlen(cdown->meta) < 1) {
                net_ev_clr(cup, EV_W);
                net_ev_add(cdown, EV_R);
                return AGAIN;
            }
        }
    }
    return OK;
}

static int tls_tunnel_up2down_recv_priority(con_t *c) {
    tls_tunnel_session_t *session = c->user_data;
    con_t *cdown = session->cdown;
    con_t *cup = session->cup;
    int ret = 0;

    net_timer_add(cup, tls_session_timeout, TLS_TMOUT);
    net_timer_add(cdown, tls_session_timeout, TLS_TMOUT);

    for (;;) {
        ret = tls_tunnel_recv(cup, cup->meta);
        if (ret == ERROR) {
            session->frecv_err_up = 1;
            if (meta_getlen(cup->meta) < 1) {
                net_free(cup);
                net_free(cdown);
                return ERROR;
            }
        } else if (ret == AGAIN) {
            if (meta_getlen(cup->meta) < 1) {
                net_ev_clr(cdown, EV_W);
                net_ev_add(cup, EV_R);
                return AGAIN;
            }
        }

        ret = tls_tunnel_send(cdown, cup->meta);
        if (ret == ERROR) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        } else if (ret == AGAIN) {
            net_ev_add(cdown, EV_W);
            net_ev_clr(cup, EV_R);
            return AGAIN;
        }

        if (session->frecv_err_up) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
        meta_clr(cup->meta);
    }
    return OK;
}

static int tls_tunnel_up2down_send_priority(con_t *c) {
    tls_tunnel_session_t *session = c->user_data;
    con_t *cdown = session->cdown;
    con_t *cup = session->cup;
    int ret = 0;

    net_timer_add(cup, tls_session_timeout, TLS_TMOUT);
    net_timer_add(cdown, tls_session_timeout, TLS_TMOUT);

    for (;;) {
        ret = tls_tunnel_send(cdown, cup->meta);
        if (ret == ERROR) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        } else if (ret == AGAIN) {
            net_ev_add(cdown, EV_W);
            net_ev_clr(cup, EV_R);
            return AGAIN;
        }

        if (session->frecv_err_up) {
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
        meta_clr(cup->meta);

        ret = tls_tunnel_recv(cup, cup->meta);
        if (ret == ERROR) {
            session->frecv_err_up = 1;
            if (meta_getlen(cup->meta) < 1) {
                net_free(cup);
                net_free(cdown);
                return ERROR;
            }
        } else if (ret == AGAIN) {
            if (meta_getlen(cup->meta) < 1) {
                net_ev_clr(cdown, EV_W);
                net_ev_add(cup, EV_R);
                return AGAIN;
            }
        }
    }
    return OK;
}


int tls_tunnel_transport(con_t *c) {
    tls_tunnel_session_t *session = c->user_data;
    con_t *cdown = session->cdown;
    con_t *cup = session->cup;

    if (!cdown->meta) {
        if (OK != meta_alloc(&cdown->meta, TLS_METAN)) {
            err("tls tunnel. cdown meta alloc\n");
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
    }
    if (!cup->meta) {
        if (OK != meta_alloc(&cup->meta, TLS_METAN)) {
            err("tls tunnel. cup meta alloc\n");
            net_free(cup);
            net_free(cdown);
            return ERROR;
        }
    }
    /// only clear up meta in here. because local run in here too.
    /// local(down) mabey recv some data.
    meta_clr(cup->meta);

    cdown->read_cb = tls_tunnel_down2up_recv_priority;
    cup->write_cb = tls_tunnel_down2up_send_priority;

    cup->read_cb = tls_tunnel_up2down_recv_priority;
    cdown->write_cb = tls_tunnel_up2down_send_priority;

    net_ev_set(cdown, EV_R);
    net_ev_set(cup, EV_R);

    if (meta_getlen(cdown->meta) > 0) {
        return cup->write_cb(cup);
    } else {
        return cdown->read_cb(cdown);
    }
}

static int tls_tunnel_s_auth_chk(con_t *cdown) {
    tls_tunnel_session_t *session = cdown->user_data;

    enum { s_mg1 = 0, s_mg2, s_len, s_data };

    for (;;) {
        if (meta_getlen(cdown->meta) < 1) {
            int recvd = cdown->recv(cdown, cdown->meta->last, meta_getfree(cdown->meta));
            if (recvd < 0) {
                if (recvd == AGAIN) {
                    net_timer_add(cdown, tls_session_timeout, TLS_TMOUT);
                    return AGAIN;
                }
                err("tls tunnel. auth recv err\n");
                return ERROR;
            }
            cdown->meta->last += recvd;
        }

        uint8_t *p = NULL;
        for (; cdown->meta->pos < cdown->meta->last; cdown->meta->pos++) {
            p = cdown->meta->pos;
            if (session->auth_state == s_mg1) {
                if (*p != TLS_AUTH_MG1) {
                    err("tls tunnel. auth chk mg1 err\n");
                    net_free(cdown);
                    return ERROR;
                }
                session->auth_state = s_mg2;
            } else if (session->auth_state == s_mg2) {
                if (*p != TLS_AUTH_MG2) {
                    err("tls tunnel. auth chk mg2 err\n");
                    net_free(cdown);
                    return ERROR;
                }
                session->auth_state = s_len;
            } else if (session->auth_state == s_len) {
                session->auth_data_all = *p;
                if (session->auth_data_all < 1 || session->auth_data_all > 31) {
                    err("tls tunnel. auth chk slen [%d] err\n", session->auth_data_all);
                    net_free(cdown);
                    return ERROR;
                }
                session->auth_state = s_data;
            } else if (session->auth_state == s_data) {
                session->auth_data[session->auth_data_recv++] = *p;
                if (session->auth_data_recv == session->auth_data_all) {
                    if (0 == ezac_find(g_ses_ctx->ac, (char*)session->auth_data, session->auth_data_all)) {
                        net_timer_del(cdown);

                        cdown->meta->pos ++;
                        cdown->read_cb = s5_p1_req;
                        cdown->write_cb = NULL;
                        return cdown->read_cb(cdown);
                    } else {
                        err("tls tunnel. auth not found\n");
                        net_free(cdown);
                        return ERROR;
                    }
                }
            }
        }
    }

    err("tls tunnel. auth chk not fin. auth_state [%d]\n", session->auth_state);
    net_free(cdown);
    return ERROR;
}

int tls_tunnel_s_start(con_t *cdown) {
    net_timer_del(cdown);
    
    if (!cdown->meta) {
        schk(OK == meta_alloc(&cdown->meta, TLS_METAN), {
            net_free(cdown);
            return ERROR;
        });
    }

    tls_tunnel_session_t *session = NULL;
    schk(0 == tls_session_alloc(&session), {
        net_free(cdown);
        return -1;
    });
    session->cdown = cdown;
    cdown->user_data = session;
    cdown->free_user_data = tls_session_release_by_cdown;
    

    /// s5
    if (OK != s5_alloc(&session->s5)) {
        err("tls tunnel. alloc s5 err\n");
        net_free(cdown);
        return ERROR;
    }

    cdown->read_cb = tls_tunnel_s_auth_chk;
    cdown->write_cb = NULL;
    return cdown->read_cb(cdown);
}

int tls_tunnel_s_accept(con_t *cdown) {
    net_timer_del(cdown);

    if (!cdown->ssl) {
        if (OK != net_ssl_create(cdown, L_SSL_SERVER)) {
            err("tls tunnel. cdown ssl create err\n");
            net_free(cdown);
            return ERROR;
        }
    }

    if (net_ssl_check_handshake_err(cdown)) {
        err("tls tunnel. ssl handshake err\n");
        net_free(cdown);
        return ERROR;
    }

    if (!net_ssl_check_handshaked(cdown)) {
        int rc = net_ssl_handshake(cdown);
        if (rc < 0) {
            if (rc == AGAIN) {
                net_timer_add(cdown, net_free_timeout, TLS_TMOUT);
                return AGAIN;
            }
            err("tls tunnel. ssl handshek err\n");
            net_free(cdown);
            return ERROR;
        }
    }

    cdown->read_cb = tls_tunnel_s_start;
    cdown->write_cb = NULL;
    return cdown->read_cb(cdown);
}

static int tls_tunnel_s_auth_mgr_fparse(char *data) {
    cJSON *root = cJSON_Parse(data);
    if (root) { /// traversal the array
        for (int i = 0; i < cJSON_GetArraySize(root); i++) {
            cJSON *arrobj = cJSON_GetArrayItem(root, i);
            if (0 != ezac_add(g_ses_ctx->ac, cJSON_GetStringValue(arrobj), strlen(cJSON_GetStringValue(arrobj)))) {
                err("tls tunnel. srv auth add into ac err\n");
            }
        }
        cJSON_Delete(root);
    }
    return OK;
}

static int tls_tunnel_s_auth_mgr_init(void) {
    schk(g_ses_ctx->ac = ezac_init(), return -1);
    sys_data_t *fdata = sys_file_read_value(config_get()->s5_serv_auth_path);
    if (fdata) {
        tls_tunnel_s_auth_mgr_fparse(fdata->data);
        ezac_compiler(g_ses_ctx->ac);
        sys_free(fdata);
    }
    return OK;
}

int tls_tunnel_s_init(void) {
    g_ses_ctx = (tls_tunnel_s_t *)mem_alloc(sizeof(tls_tunnel_s_t));
    if (g_ses_ctx) {
        if (config_get()->s5_mode == TLS_TUNNEL_S ||
            config_get()->s5_mode == TLS_TUNNEL_S_SCRECT) {
            schk(tls_tunnel_s_auth_mgr_init() == 0, return ERROR);

            struct sockaddr_in addr;
            memset(&addr, 0x0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(config_get()->s5_serv_port);
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            
            net_listen(tls_tunnel_s_accept,    &addr, 1);
        }
    }
    return OK;
}

int tls_tunnel_s_exit(void) {
    if (g_ses_ctx) {
        if (g_ses_ctx->ac)
            ezac_free(g_ses_ctx->ac);

        mem_free((void *)g_ses_ctx);
        g_ses_ctx = NULL;
    }
    return OK;
}
