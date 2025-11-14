
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if !(NGX_WIN32)

static void ngx_close_accepted_udp_connection(ngx_connection_t *c);
static ssize_t ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_int_t ngx_insert_udp_connection(ngx_connection_t *c);
static ngx_connection_t *ngx_lookup_udp_connection(ngx_listening_t *ls,
    struct sockaddr *sockaddr, socklen_t socklen,
    struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
ngx_event_recvmsg(ngx_event_t *ev)
{
    ssize_t            n;
    ngx_buf_t          buf;
    ngx_log_t         *log;
    ngx_err_t          err;
    socklen_t          socklen, local_socklen;
    ngx_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    ngx_sockaddr_t     sa, lsa;
    struct sockaddr   *sockaddr, *local_sockaddr;
    ngx_listening_t   *ls;
    ngx_event_conf_t  *ecf;
    ngx_connection_t  *c, *lc;
    static u_char      buffer[65535];

#if (NGX_HAVE_MSGHDR_MSG_CONTROL                                         \
    && (NGX_HAVE_ADDRINFO_CMSG || NGX_HAVE_UNIX_DOMAIN))
    u_char             msg_control[NGX_UDP_CMSG_SIZE];
#endif

    if (ev->timedout) {
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        ngx_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(ngx_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL                                         \
    && (NGX_HAVE_ADDRINFO_CMSG || NGX_HAVE_UNIX_DOMAIN))
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

#if (NGX_HAVE_UNIX_DOMAIN)
        if (ls->sockaddr->sa_family == AF_UNIX) {
            msg.msg_control = msg_control;
            msg.msg_controllen = sizeof(msg_control);
        }
#endif

#if (NGX_HAVE_ADDRINFO_CMSG)
        if (msg.msg_control == NULL && ls->wildcard) {
            msg.msg_control = msg_control;
            msg.msg_controllen = sizeof(msg_control);
        }
#endif

        if (msg.msg_control) {
            ngx_memzero(msg_control, sizeof(msg_control));
        }
#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (NGX_HAVE_MSGHDR_MSG_CONTROL && NGX_HAVE_UNIX_DOMAIN)
        if (ls->sockaddr->sa_family == AF_UNIX && msg.msg_control) {
            struct cmsghdr           *cmsg;
            ngx_socket_t              passed_fd;
            int                       fd;
            struct sockaddr_storage   ps, lsock;
            socklen_t                 plen, llen;

            passed_fd = (ngx_socket_t) -1;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (cmsg->cmsg_level != SOL_SOCKET
                    || cmsg->cmsg_type != SCM_RIGHTS)
                {
                    continue;
                }

                if (cmsg->cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                                  "recvmsg() returned too small ancillary "
                                  "data for SCM_RIGHTS");
                    break;
                }

                ngx_memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
                passed_fd = (ngx_socket_t) fd;
                break;
            }

            if (passed_fd != (ngx_socket_t) -1) {

                if (msg.msg_flags & MSG_CTRUNC) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                                  "recvmsg() truncated ancillary data");
                    if (ngx_close_socket(passed_fd) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }
                    continue;
                }

                plen = sizeof(ps);
                if (getpeername(passed_fd, (struct sockaddr *) &ps, &plen)
                    == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  "getpeername() failed for passed connection");
                    if (ngx_close_socket(passed_fd) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }
                    continue;
                }

                llen = sizeof(lsock);
                if (getsockname(passed_fd, (struct sockaddr *) &lsock, &llen)
                    == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  "getsockname() failed for passed connection");
                    if (ngx_close_socket(passed_fd) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }
                    continue;
                }

#if (NGX_STAT_STUB)
                (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

                ngx_accept_disabled = ngx_cycle->connection_n / 8
                                      - ngx_cycle->free_connection_n;

                if (ngx_event_accept_connection(ev, passed_fd, SOCK_STREAM,
                                                (struct sockaddr *) &ps, plen,
                                                (struct sockaddr *) &lsock,
                                                llen, 1, ecf)
                    != NGX_OK)
                {
                    return;
                }

                if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                continue;
            }
        }
#endif

#if (NGX_HAVE_ADDRINFO_CMSG)
        if (ls->wildcard && (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            socklen = sizeof(ngx_sockaddr_t);
        }

        if (socklen == 0) {

            /*
             * on Linux recvmsg() returns zero msg_namelen
             * when receiving packets from unbound AF_UNIX sockets
             */

            socklen = sizeof(struct sockaddr);
            ngx_memzero(&sa, sizeof(struct sockaddr));
            sa.sockaddr.sa_family = ls->sockaddr->sa_family;
        }

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (NGX_HAVE_ADDRINFO_CMSG)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            ngx_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (ngx_get_srcaddr_cmsg(cmsg, local_sockaddr) == NGX_OK) {
                    break;
                }
            }
        }

#endif

        c = ngx_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
                                      local_socklen);

        if (c) {

#if (NGX_DEBUG)
            if (c->log->log_level & NGX_LOG_DEBUG_EVENT) {
                ngx_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            ngx_memzero(&buf, sizeof(ngx_buf_t));

            buf.pos = buffer;
            buf.last = buffer + n;

            rev = c->read;

            c->udp->buffer = &buf;

            rev->ready = 1;
            rev->active = 0;

            rev->handler(rev);

            if (c->udp) {
                c->udp->buffer = NULL;
            }

            rev->ready = 0;
            rev->active = 1;

            goto next;
        }

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        c = ngx_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        c->sockaddr = ngx_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        ngx_memcpy(c->sockaddr, sockaddr, socklen);

        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        *log = ls->log;

        c->recv = ngx_udp_shared_recv;
        c->send = ngx_udp_send;
        c->send_chain = ngx_udp_send_chain;

        c->need_flush_buf = 1;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = ngx_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                ngx_close_accepted_udp_connection(c);
                return;
            }

            ngx_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = ngx_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        c->buffer->last = ngx_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        c->start_time = ngx_current_msec;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_udp_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_udp_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        if (ngx_insert_udp_connection(c) != NGX_OK) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
ngx_close_accepted_udp_connection(ngx_connection_t *c)
{
    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


static ssize_t
ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    ngx_buf_t  *b;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return NGX_AGAIN;
    }

    b = c->udp->buffer;

    n = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, n);

    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


void
ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_int_t               rc;
    ngx_connection_t       *c, *ct;
    ngx_rbtree_node_t     **p;
    ngx_udp_connection_t   *udp, *udpt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (ngx_udp_connection_t *) node;
            c = udp->connection;

            udpt = (ngx_udp_connection_t *) temp;
            ct = udpt->connection;

            rc = ngx_memn2cmp(udp->key.data, udpt->key.data,
                              udp->key.len, udpt->key.len);

            if (rc == 0 && c->listening->wildcard) {
                rc = ngx_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
                                      ct->local_sockaddr, ct->local_socklen, 1);
            }

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_insert_udp_connection(ngx_connection_t *c)
{
    uint32_t               hash;
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *udp;

    if (c->udp) {
        return NGX_OK;
    }

    udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
    if (udp == NULL) {
        return NGX_ERROR;
    }

    udp->connection = c;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        ngx_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    ngx_crc32_final(hash);

    udp->node.key = hash;
    udp->key.data = (u_char *) c->sockaddr;
    udp->key.len = c->socklen;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->data = c;
    cln->handler = ngx_delete_udp_connection;

    ngx_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return NGX_OK;
}


void
ngx_delete_udp_connection(void *data)
{
    ngx_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    ngx_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


static ngx_connection_t *
ngx_lookup_udp_connection(ngx_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_udp_connection_t  *udp;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        ngx_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

    ngx_crc32_final(hash);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        udp = (ngx_udp_connection_t *) node;

        c = udp->connection;

        rc = ngx_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = ngx_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#else

void
ngx_delete_udp_connection(void *data)
{
    return;
}

#endif
