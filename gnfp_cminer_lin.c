/*
 * gnfp_cminer.c — GNFPHash 1.0.5 CPU miner (Ubuntu / Linux)
 * Dual-connection 5% fee + local counters + fast hash + fixed selftest
 *
 * Build: gcc -O3 -march=native -pthread -o gnfp_cminer cminer.c -lssl -lcrypto
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define CLIENT              "GNFPHash"
#define VERSION             "1.0.5"
#define ALGORITHM           "GNFPHash"
#define PERSONAL            "GNFPHash-v1"
#define ROUNDS              8
#define NONCE_HEX           16
#define HASH_FIELD_MAX      256
#define SHARE_Q             256
#define MAX_IN_FLIGHT       16
#define INFLIGHT_TO_MS      5000
#define STATS_MS            1000
#define STATUS_MS           5000
#define DEV_FEE_PCT         5
#define DEV_FEE_EVERY       20
#define DEV_FEE_ADDR        "gnfp19381c4b1d7a9cbae64120f24b16d248ae07c6ff1"
#define DEFAULT_HOST        "de.restoreprivacy.online"
#define DEFAULT_PORT        1474
#define LOCAL_FLUSH         16384ull

typedef struct {
    char job_id[128];
    char nonce[NONCE_HEX + 1];
    int  bits;
    int  is_fee;
} share_t;

typedef struct {
    char job_id[128];
    char pre[HASH_FIELD_MAX + 1];
    size_t pre_len;
    int  bits;
    int  height;
    uint64_t gen;
} job_t;

typedef struct {
    char host[160];
    int  port;
    int  tls;
    int  threads;
    char address[256];
    char worker[64];
    char user[320];
    char fee_user[320];
    char fee_worker[32];
    int  cpu_cores, cpu_threads, smt, max_threads;
    char platform[32], arch[32];
} cfg_t;

typedef struct {
    int fd;
    SSL *ssl;
    pthread_mutex_t mu;
} conn_t;

static volatile int g_run = 1;
static int g_sig_hits = 0;

static job_t g_job, g_fee_job;
static int g_fee_ready = 0;
static pthread_mutex_t g_job_mu = PTHREAD_MUTEX_INITIALIZER;

static share_t g_q[SHARE_Q];
static int g_q_head = 0, g_q_tail = 0, g_q_n = 0;
static pthread_mutex_t g_q_mu = PTHREAD_MUTEX_INITIALIZER;

static int g_inflight[2];
static uint64_t g_inflight_ts[2][MAX_IN_FLIGHT];
static int g_inflight_fee[2][MAX_IN_FLIGHT];
static int g_if_n[2];

static conn_t g_mainc = {-1, NULL, PTHREAD_MUTEX_INITIALIZER};
static conn_t g_feec  = {-1, NULL, PTHREAD_MUTEX_INITIALIZER};
static SSL_CTX *g_ctx = NULL;

static uint64_t g_hash_calls = 0;
static uint64_t g_shares_found = 0;
static uint64_t g_shares_found16 = 0;
static uint64_t g_shares_pushed = 0;
static uint64_t g_shares_dropped = 0;
static uint64_t g_shares_submitted = 0;
static uint64_t g_accepts = 0;
static uint64_t g_rejects = 0;
static uint64_t g_implausible = 0;
static uint64_t g_blocks = 0;
static uint64_t g_fee_accepts = 0;
static uint64_t g_fee_submitted = 0;
static uint64_t g_t0_ms = 0;
static uint64_t g_first_accept_ms = 0;
static int      g_last_bits = 14;
static uint64_t g_backoff_until = 0;
static int      g_accept_print_left = 8;
static int      g_nthreads = 1;

static void on_sig(int s) {
    (void)s;
    g_run = 0;
    if (++g_sig_hits >= 2) _exit(1);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void nonce_hex16(uint64_t n, char out[NONCE_HEX + 1]) {
    static const char *h = "0123456789abcdef";
    for (int i = NONCE_HEX - 1; i >= 0; i--) {
        out[i] = h[n & 15];
        n >>= 4;
    }
    out[NONCE_HEX] = 0;
}

static int meets_target(const unsigned char *hash, int bits) {
    if (bits <= 0) return 1;
    if (bits > 256) bits = 256;
    int full = bits / 8;
    int rem  = bits % 8;
    for (int i = 0; i < full; i++) if (hash[i]) return 0;
    if (!rem) return 1;
    return hash[full] < (1 << (8 - rem));
}

static void gnfp_hash(const char *pre, size_t pre_len, const char nonce[16],
                      unsigned char out[32]) {
    unsigned char acc[32];
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, PERSONAL, 11);
    SHA256_Update(&c, ALGORITHM, 8);
    SHA256_Update(&c, pre, pre_len);
    SHA256_Update(&c, nonce, 16);
    SHA256_Final(acc, &c);
    for (int r = 0; r < ROUNDS; r++) {
        char tag = '0' + r;
        SHA256_Init(&c);
        SHA256_Update(&c, acc, 32);
        SHA256_Update(&c, PERSONAL, 11);
        SHA256_Update(&c, &tag, 1);
        SHA256_Update(&c, pre, pre_len);
        SHA256_Update(&c, nonce, 16);
        SHA256_Final(acc, &c);
    }
    memcpy(out, acc, 32);
}

static void hash_to_hex(const unsigned char *h, char out[65]) {
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = d[h[i] >> 4];
        out[i * 2 + 1] = d[h[i] & 15];
    }
    out[64] = 0;
}

static int json_str(const char *line, const char *key, char *dst, size_t cap) {
    char pat[80];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(line, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        dst[n++] = *p++;
    }
    dst[n] = 0;
    return 1;
}

static int json_int(const char *line, const char *key, long *out) {
    char pat[80];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(line, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return 0;
    *out = v;
    return 1;
}

static int share_seen(const char *job_id, const char *nonce) {
    for (int i = 0, idx = g_q_head; i < g_q_n; i++, idx = (idx + 1) % SHARE_Q)
        if (!strcmp(g_q[idx].job_id, job_id) && !memcmp(g_q[idx].nonce, nonce, NONCE_HEX))
            return 1;
    return 0;
}

static int share_push(const char *job_id, const char *nonce, int bits, int is_fee) {
    int ok = 0;
    pthread_mutex_lock(&g_q_mu);
    if (g_q_n < SHARE_Q && job_id[0] && nonce && !share_seen(job_id, nonce)) {
        share_t *s = &g_q[g_q_tail];
        snprintf(s->job_id, sizeof(s->job_id), "%s", job_id);
        memcpy(s->nonce, nonce, NONCE_HEX);
        s->nonce[NONCE_HEX] = 0;
        s->bits = bits;
        s->is_fee = is_fee;
        g_q_tail = (g_q_tail + 1) % SHARE_Q;
        g_q_n++;
        ok = 1;
    }
    pthread_mutex_unlock(&g_q_mu);
    if (ok) __sync_fetch_and_add(&g_shares_pushed, 1);
    else    __sync_fetch_and_add(&g_shares_dropped, 1);
    return ok;
}

static int share_pop(share_t *out) {
    pthread_mutex_lock(&g_q_mu);
    if (g_q_n <= 0) { pthread_mutex_unlock(&g_q_mu); return 0; }
    *out = g_q[g_q_head];
    g_q_head = (g_q_head + 1) % SHARE_Q;
    g_q_n--;
    pthread_mutex_unlock(&g_q_mu);
    return 1;
}

static void share_drop_stale(void) {
    pthread_mutex_lock(&g_q_mu);
    g_q_head = g_q_tail = g_q_n = 0;
    pthread_mutex_unlock(&g_q_mu);
}

static void inflight_release_timeouts(int which) {
    uint64_t t = now_ms();
    pthread_mutex_lock(&g_q_mu);
    int w = 0;
    for (int i = 0; i < g_if_n[which]; i++) {
        if (t - g_inflight_ts[which][i] < INFLIGHT_TO_MS) {
            g_inflight_ts[which][w] = g_inflight_ts[which][i];
            g_inflight_fee[which][w] = g_inflight_fee[which][i];
            w++;
        } else g_inflight[which]--;
    }
    g_if_n[which] = w;
    if (g_inflight[which] < 0) g_inflight[which] = 0;
    pthread_mutex_unlock(&g_q_mu);
}

static void inflight_add(int which, int is_fee) {
    pthread_mutex_lock(&g_q_mu);
    if (g_if_n[which] < MAX_IN_FLIGHT) {
        g_inflight_ts[which][g_if_n[which]] = now_ms();
        g_inflight_fee[which][g_if_n[which]] = is_fee;
        g_if_n[which]++;
        g_inflight[which]++;
    }
    pthread_mutex_unlock(&g_q_mu);
}

static int inflight_ack(int which, int *was_fee) {
    pthread_mutex_lock(&g_q_mu);
    int fee = 0;
    if (g_if_n[which] > 0) {
        fee = g_inflight_fee[which][0];
        memmove(g_inflight_ts[which], g_inflight_ts[which] + 1, (g_if_n[which] - 1) * sizeof(uint64_t));
        memmove(g_inflight_fee[which], g_inflight_fee[which] + 1, (g_if_n[which] - 1) * sizeof(int));
        g_if_n[which]--;
        if (g_inflight[which] > 0) g_inflight[which]--;
    }
    pthread_mutex_unlock(&g_q_mu);
    if (was_fee) *was_fee = fee;
    return 1;
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int tcp_connect(const char *host, int port) {
    char pbuf[16];
    snprintf(pbuf, sizeof(pbuf), "%d", port);
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, pbuf, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void conn_close(conn_t *c) {
    pthread_mutex_lock(&c->mu);
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    pthread_mutex_unlock(&c->mu);
}

static int conn_alive(conn_t *c) {
    return c->fd >= 0;
}

static int conn_connect(conn_t *c, const cfg_t *cfg) {
    conn_close(c);
    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) return -1;
    if (cfg->tls) {
        if (!g_ctx) {
            SSL_library_init();
            SSL_load_error_strings();
            g_ctx = SSL_CTX_new(TLS_client_method());
            if (!g_ctx) { close(fd); return -1; }
            SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
        }
        SSL *ssl = SSL_new(g_ctx);
        SSL_set_tlsext_host_name(ssl, cfg->host);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(fd); return -1; }
        c->ssl = ssl;
    }
    set_nonblock(fd);
    c->fd = fd;
    return 0;
}

static int net_send_raw(conn_t *c, const char *buf, int n) {
    int off = 0;
    while (off < n && g_run) {
        pthread_mutex_lock(&c->mu);
        int w = 0;
        if (c->ssl) {
            w = SSL_write(c->ssl, buf + off, n - off);
            if (w <= 0) {
                int e = SSL_get_error(c->ssl, w);
                pthread_mutex_unlock(&c->mu);
                if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
                    usleep(1000);
                    continue;
                }
                return -1;
            }
        } else if (c->fd >= 0) {
            w = (int)write(c->fd, buf + off, (size_t)(n - off));
            if (w < 0) {
                int err = errno;
                pthread_mutex_unlock(&c->mu);
                if (err == EAGAIN || err == EWOULDBLOCK) {
                    usleep(1000);
                    continue;
                }
                return -1;
            }
        } else {
            pthread_mutex_unlock(&c->mu);
            return -1;
        }
        pthread_mutex_unlock(&c->mu);
        off += w;
    }
    return off == n ? 0 : -1;
}

static int net_send_line(conn_t *c, const char *json) {
    char buf[2048];
    int n = snprintf(buf, sizeof(buf), "%s\n", json);
    if (n <= 0 || n >= (int)sizeof(buf)) return -1;
    return net_send_raw(c, buf, n);
}

static void ident_json(char *dst, size_t cap, const cfg_t *cfg, const char *login, int threads) {
    snprintf(dst, cap,
        "\"login\":\"%s\",\"threads\":%d,"
        "\"cpuCores\":%d,\"cpuThreads\":%d,\"smt\":%d,\"maxThreads\":%d,"
        "\"platform\":\"%s\",\"arch\":\"%s\","
        "\"client\":\"%s\",\"version\":\"%s\",\"algorithm\":\"%s\"",
        login, threads, cfg->cpu_cores, cfg->cpu_threads, cfg->smt, cfg->max_threads,
        cfg->platform, cfg->arch, CLIENT, VERSION, ALGORITHM);
}

static int send_login_conn(conn_t *c, const cfg_t *cfg, const char *login, int threads) {
    char id[768], msg[1024];
    ident_json(id, sizeof(id), cfg, login, threads);
    snprintf(msg, sizeof(msg), "{\"method\":\"login\",%s,\"id\":1,\"jsonrpc\":\"2.0\"}", id);
    return net_send_line(c, msg);
}

static int send_stats_conn(conn_t *c, const cfg_t *cfg, const char *login, double hr, uint64_t hashes, const char *jid, int height) {
    char id[768], msg[1400];
    ident_json(id, sizeof(id), cfg, login, cfg->threads);
    snprintf(msg, sizeof(msg),
        "{\"method\":\"stats\",%s,\"hashrate\":%.0f,\"hashes\":%llu,"
        "\"jobId\":\"%s\",\"height\":%d,\"jsonrpc\":\"2.0\"}",
        id, hr, (unsigned long long)hashes, jid && jid[0] ? jid : "", height);
    return net_send_line(c, msg);
}

static int send_submit_conn(conn_t *c, const cfg_t *cfg, const char *login, int threads, const share_t *s) {
    char id[768], msg[1600];
    ident_json(id, sizeof(id), cfg, login, threads);
    snprintf(msg, sizeof(msg),
        "{\"method\":\"submit\",%s,\"id\":\"%s\",\"nonce\":\"%s\","
        "\"output\":\"\",\"jobId\":\"%s\",\"jsonrpc\":\"2.0\"}",
        id, s->job_id, s->nonce, s->job_id);
    return net_send_line(c, msg);
}

static void *hash_worker(void *arg) {
    int tid = (int)(intptr_t)arg;
    uint64_t nonce = (uint64_t)tid + 1;
    char nhex[NONCE_HEX + 1];
    unsigned char dig[32];
    uint64_t seen_gen = 0, seen_fee_gen = 0;
    char pre[HASH_FIELD_MAX + 1], fee_pre[HASH_FIELD_MAX + 1];
    size_t pre_len = 0, fee_pre_len = 0;
    char job_id[128], fee_job_id[128];
    int bits = 14, fee_bits = 14;
    job_id[0] = fee_job_id[0] = 0;

    uint64_t local_hashes = 0, local_found = 0, local_found16 = 0;

    while (g_run) {
        pthread_mutex_lock(&g_job_mu);
        if (g_job.gen != seen_gen) {
            memcpy(pre, g_job.pre, g_job.pre_len);
            pre_len = g_job.pre_len;
            snprintf(job_id, sizeof(job_id), "%s", g_job.job_id);
            bits = g_job.bits;
            seen_gen = g_job.gen;
            nonce = (uint64_t)tid + 1;
        }
        if (g_fee_ready && g_fee_job.gen != seen_fee_gen) {
            memcpy(fee_pre, g_fee_job.pre, g_fee_job.pre_len);
            fee_pre_len = g_fee_job.pre_len;
            snprintf(fee_job_id, sizeof(fee_job_id), "%s", g_fee_job.job_id);
            fee_bits = g_fee_job.bits;
            seen_fee_gen = g_fee_job.gen;
        }
        pthread_mutex_unlock(&g_job_mu);

        if (!job_id[0] || !pre_len) {
            usleep(2000);
            continue;
        }

        int is_fee = ((nonce % DEV_FEE_EVERY) == 0) && g_fee_ready && fee_job_id[0];

        const char *use_pre = is_fee ? fee_pre : pre;
        size_t use_len = is_fee ? fee_pre_len : pre_len;
        const char *use_jid = is_fee ? fee_job_id : job_id;
        int use_bits = is_fee ? fee_bits : bits;

        nonce_hex16(nonce, nhex);
        gnfp_hash(use_pre, use_len, nhex, dig);
        local_hashes++;

        if (meets_target(dig, use_bits)) {
            local_found++;
            if (meets_target(dig, use_bits + 2)) local_found16++;
            share_push(use_jid, nhex, use_bits, is_fee);
        }

        if (local_hashes >= LOCAL_FLUSH) {
            __sync_fetch_and_add(&g_hash_calls, local_hashes);
            __sync_fetch_and_add(&g_shares_found, local_found);
            __sync_fetch_and_add(&g_shares_found16, local_found16);
            local_hashes = local_found = local_found16 = 0;
        }
        nonce += (uint64_t)g_nthreads;
    }

    if (local_hashes) {
        __sync_fetch_and_add(&g_hash_calls, local_hashes);
        __sync_fetch_and_add(&g_shares_found, local_found);
        __sync_fetch_and_add(&g_shares_found16, local_found16);
    }
    return NULL;
}
static int classify_reply(const char *line) {
    if (strstr(line, "\"result\":true") || strstr(line, "\"status\":\"OK\"")) return 1;
    if (strstr(line, "implausible_rate")) return 3;
    if (strstr(line, "block") || strstr(line, "\"isBlock\":true")) return 4;
    if (strstr(line, "\"result\":false") || strstr(line, "reject")) return 2;
    return 0;
}

static void apply_job_line(const char *line, int is_fee) {
    char jid[128] = {0}, pre[HASH_FIELD_MAX + 1] = {0};
    long bits = 14, height = 0;
    if (!json_str(line, "jobId", jid, sizeof(jid))) return;
    if (!json_str(line, "input", pre, sizeof(pre)) && !json_str(line, "preWork", pre, sizeof(pre))) return;
    json_int(line, "difficulty", &bits);
    json_int(line, "height", &height);
    if (bits < 1) bits = 14;
    if (bits > 32) bits = 32;

    pthread_mutex_lock(&g_job_mu);
    if (is_fee) {
        snprintf(g_fee_job.job_id, sizeof(g_fee_job.job_id), "%s", jid);
        snprintf(g_fee_job.pre, sizeof(g_fee_job.pre), "%s", pre);
        g_fee_job.pre_len = strlen(pre);
        g_fee_job.bits = (int)bits;
        g_fee_job.height = (int)height;
        g_fee_job.gen++;
        g_fee_ready = 1;
    } else {
        snprintf(g_job.job_id, sizeof(g_job.job_id), "%s", jid);
        snprintf(g_job.pre, sizeof(g_job.pre), "%s", pre);
        g_job.pre_len = strlen(pre);
        g_job.bits = (int)bits;
        g_job.height = (int)height;
        g_job.gen++;
        g_last_bits = (int)bits;
    }
    pthread_mutex_unlock(&g_job_mu);
}

static void print_status(const cfg_t *cfg) {
    uint64_t now = now_ms();
    double elapsed = (now - g_t0_ms) / 1000.0;
    if (elapsed < 0.1) elapsed = 0.1;
    double call = g_hash_calls / elapsed;
    double proven = (g_accepts * (1ull << g_last_bits)) / elapsed;
    printf("[status] call=%.0f H/s  proven=%.0f H/s  find=%llu  sub=%llu  acc=%llu  rej=%llu  fee_acc=%llu  q=%d  if=%d/%d  bits=%d\n",
           call, proven,
           (unsigned long long)g_shares_found,
           (unsigned long long)g_shares_submitted,
           (unsigned long long)g_accepts,
           (unsigned long long)g_rejects,
           (unsigned long long)g_fee_accepts,
           g_q_n, g_inflight[0], g_inflight[1], g_last_bits);
    fflush(stdout);
}

static void flush_submits(const cfg_t *cfg) {
    share_t s;
    while (share_pop(&s)) {
        int which = s.is_fee ? 1 : 0;
        conn_t *c = s.is_fee ? &g_feec : &g_mainc;
        const char *login = s.is_fee ? cfg->fee_user : cfg->user;
        if (!conn_alive(c)) continue;
        if (g_inflight[which] >= MAX_IN_FLIGHT) {
            share_push(s.job_id, s.nonce, s.bits, s.is_fee);
            break;
        }
        if (send_submit_conn(c, cfg, login, cfg->threads, &s) == 0) {
            inflight_add(which, s.is_fee);
            __sync_fetch_and_add(&g_shares_submitted, 1);
            if (s.is_fee) __sync_fetch_and_add(&g_fee_submitted, 1);
        }
    }
}

static void handle_line(const char *line, int is_fee, const cfg_t *cfg) {
    if (strstr(line, "\"method\":\"job\"") || strstr(line, "\"jobId\"")) {
        apply_job_line(line, is_fee);
        return;
    }
    int cls = classify_reply(line);
    if (cls == 1) {
        int was_fee = 0;
        inflight_ack(is_fee ? 1 : 0, &was_fee);
        __sync_fetch_and_add(&g_accepts, 1);
        if (was_fee || is_fee) __sync_fetch_and_add(&g_fee_accepts, 1);
        if (!g_first_accept_ms) g_first_accept_ms = now_ms();
        if (g_accept_print_left > 0) {
            printf("[accept] %s\n", is_fee ? "(fee)" : "");
            g_accept_print_left--;
        }
    } else if (cls == 2) {
        inflight_ack(is_fee ? 1 : 0, NULL);
        __sync_fetch_and_add(&g_rejects, 1);
    } else if (cls == 3) {
        __sync_fetch_and_add(&g_implausible, 1);
        g_backoff_until = now_ms() + 8000;
        printf("[backoff] implausible_rate — pausing submits 8s\n");
    } else if (cls == 4) {
        __sync_fetch_and_add(&g_blocks, 1);
        printf("[BLOCK] !\n");
    }
}

static int pump_reads(conn_t *c, int is_fee, const cfg_t *cfg) {
    static char buf[2][8192];
    static int len[2] = {0, 0};
    int idx = is_fee ? 1 : 0;
    char *b = buf[idx];
    int *l = &len[idx];

    if (!conn_alive(c)) return -1;

    char tmp[2048];
    int n = 0;
    pthread_mutex_lock(&c->mu);
    if (c->ssl) {
        n = SSL_read(c->ssl, tmp, sizeof(tmp) - 1);
        if (n <= 0) {
            int e = SSL_get_error(c->ssl, n);
            pthread_mutex_unlock(&c->mu);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
    } else {
        n = (int)read(c->fd, tmp, sizeof(tmp) - 1);
        if (n <= 0) {
            pthread_mutex_unlock(&c->mu);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
            return -1;
        }
    }
    pthread_mutex_unlock(&c->mu);

    if (*l + n >= (int)sizeof(buf[0])) *l = 0;
    memcpy(b + *l, tmp, n);
    *l += n;
    b[*l] = 0;

    char *start = b;
    char *nl;
    while ((nl = strchr(start, '\n'))) {
        *nl = 0;
        if (nl > start) handle_line(start, is_fee, cfg);
        start = nl + 1;
    }
    int left = (int)(b + *l - start);
    if (left > 0) memmove(b, start, left);
    *l = left;
    return 0;
}

static void inventory(cfg_t *cfg) {
    cfg->cpu_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    cfg->cpu_threads = cfg->cpu_cores;
    cfg->smt = 0;
    cfg->max_threads = cfg->cpu_threads;
    snprintf(cfg->platform, sizeof(cfg->platform), "linux");
    snprintf(cfg->arch, sizeof(cfg->arch), "x86_64");
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        int cores = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "cpu cores", 9) == 0) {
                int c = 0;
                if (sscanf(line, "cpu cores : %d", &c) == 1 && c > cores) cores = c;
            }
        }
        fclose(f);
        if (cores > 0) cfg->cpu_cores = cores;
        if (cfg->cpu_threads > cfg->cpu_cores) cfg->smt = 1;
    }
}

static void setup_fee(cfg_t *cfg) {
    snprintf(cfg->fee_worker, sizeof(cfg->fee_worker), "cunt");
    snprintf(cfg->fee_user, sizeof(cfg->fee_user), "%s.%s", DEV_FEE_ADDR, cfg->fee_worker);
}

static int valid_addr(const char *a) {
    return a && a[0] && strlen(a) > 10 && strncmp(a, "gnfp", 4) == 0;
}

static int parse_user(cfg_t *cfg, const char *u) {
    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s", u);
    char *dot = strchr(tmp, '.');
    if (dot) {
        *dot = 0;
        snprintf(cfg->address, sizeof(cfg->address), "%s", tmp);
        snprintf(cfg->worker, sizeof(cfg->worker), "%s", dot + 1);
    } else {
        snprintf(cfg->address, sizeof(cfg->address), "%s", tmp);
        snprintf(cfg->worker, sizeof(cfg->worker), "x");
    }
    snprintf(cfg->user, sizeof(cfg->user), "%s.%s", cfg->address, cfg->worker);
    return valid_addr(cfg->address);
}

static int selftest(void) {
    const char *pre = "test-prework";
    const char *nonce = "0000000000000001";
    unsigned char dig[32];
    char hex[65];
    gnfp_hash(pre, strlen(pre), nonce, dig);
    hash_to_hex(dig, hex);
    const char *expect = "986437c40fee8a876e0ca3f1e58b14fa38785a179f57f98ebbb0fb03102bd4eb";
    if (strcmp(hex, expect) != 0) {
        fprintf(stderr, "selftest FAIL hash %s != %s\n", hex, expect);
        return 1;
    }

    /* correct synthetic target test */
    unsigned char z14[32] = {0};
    z14[1] = 3;
    if (!meets_target(z14, 14) || meets_target(z14, 16)) {
        fprintf(stderr, "selftest FAIL target\n");
        return 1;
    }

    printf("selftest OK\n");
    return 0;
}

static int bench(int seconds, int threads) {
    g_nthreads = threads;
    g_run = 1;
    pthread_t *th = calloc(threads, sizeof(*th));
    g_t0_ms = now_ms();
    for (int i = 0; i < threads; i++)
        pthread_create(&th[i], NULL, hash_worker, (void *)(intptr_t)i);
    sleep(seconds);
    g_run = 0;
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
    free(th);
    double elapsed = (now_ms() - g_t0_ms) / 1000.0;
    printf("bench: %.0f H/s (%d threads, %d s)\n", g_hash_calls / elapsed, threads, seconds);
    return 0;
}

static void usage(void) {
    printf("Usage: ./gnfp_cminer --user ADDRESS.WORKER [--threads N] [--pool host:port] [--notls] [--selftest] [--bench SECS]\n");
}

int main(int argc, char **argv) {
    cfg_t cfg = {0};
    cfg.port = DEFAULT_PORT;
    cfg.tls = 1;
    cfg.threads = 1;
    snprintf(cfg.host, sizeof(cfg.host), "%s", DEFAULT_HOST);

    int do_self = 0, do_bench = 0, bench_s = 10;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--user") && i + 1 < argc) {
            if (!parse_user(&cfg, argv[++i])) {
                fprintf(stderr, "bad address\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
            cfg.threads = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--pool") && i + 1 < argc) {
            char *p = argv[++i];
            char *c = strrchr(p, ':');
            if (c) {
                *c = 0;
                snprintf(cfg.host, sizeof(cfg.host), "%s", p);
                cfg.port = atoi(c + 1);
                *c = ':';
            } else {
                snprintf(cfg.host, sizeof(cfg.host), "%s", p);
            }
        } else if (!strcmp(argv[i], "--notls")) {
            cfg.tls = 0;
        } else if (!strcmp(argv[i], "--selftest")) {
            do_self = 1;
        } else if (!strcmp(argv[i], "--bench") && i + 1 < argc) {
            do_bench = 1;
            bench_s = atoi(argv[++i]);
        } else {
            usage();
            return 2;
        }
    }

    inventory(&cfg);
    setup_fee(&cfg);
    if (cfg.threads < 1) cfg.threads = 1;
    if (cfg.threads > 256) cfg.threads = 256;
    g_nthreads = cfg.threads;

    if (do_self) return selftest();
    if (do_bench) return bench(bench_s, cfg.threads);

    if (!cfg.user[0]) {
        usage();
        return 2;
    }

    printf("GNFPHash %s → %s://%s:%d user=%s threads=%d coin=GNFP algo=%s\n",
           VERSION, cfg.tls ? "tls" : "tcp", cfg.host, cfg.port,
           cfg.user, cfg.threads, ALGORITHM);
    printf("declared fee %d%% → %s (worker %s)\n",
           DEV_FEE_PCT, DEV_FEE_ADDR, cfg.fee_worker);
    printf("device cpuCores=%d cpuThreads=%d smt=%d maxThreads=%d %s/%s\n",
           cfg.cpu_cores, cfg.cpu_threads, cfg.smt, cfg.max_threads,
           cfg.platform, cfg.arch);
    fflush(stdout);

    if (selftest() != 0) return 3;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    g_t0_ms = now_ms();
    pthread_t *th = calloc((size_t)cfg.threads, sizeof(*th));
    if (!th) return 1;
    for (int i = 0; i < cfg.threads; i++)
        pthread_create(&th[i], NULL, hash_worker, (void *)(intptr_t)i);

    int fee_ok = 0;
    uint64_t last_stats = 0, last_status = 0;

    while (g_run) {
        if (!conn_alive(&g_mainc)) {
            printf("connecting main...\n");
            if (conn_connect(&g_mainc, &cfg) == 0) {
                send_login_conn(&g_mainc, &cfg, cfg.user, cfg.threads);
            } else {
                sleep(3);
                continue;
            }
        }
        if (!conn_alive(&g_feec)) {
            if (conn_connect(&g_feec, &cfg) == 0) {
                send_login_conn(&g_feec, &cfg, cfg.fee_user, 1);
                fee_ok = 1;
                printf("fee connection up (worker %s)\n", cfg.fee_worker);
            }
        }

        pump_reads(&g_mainc, 0, &cfg);
        if (fee_ok) pump_reads(&g_feec, 1, &cfg);

        inflight_release_timeouts(0);
        inflight_release_timeouts(1);

        if (now_ms() >= g_backoff_until)
            flush_submits(&cfg);

        uint64_t now = now_ms();
        if (now - last_stats >= STATS_MS) {
            double hr = g_hash_calls / ((now - g_t0_ms) / 1000.0 + 0.001);
            send_stats_conn(&g_mainc, &cfg, cfg.user, hr, g_hash_calls, g_job.job_id, g_job.height);
            if (fee_ok)
                send_stats_conn(&g_feec, &cfg, cfg.fee_user, hr * 0.05, g_hash_calls / 20, g_fee_job.job_id, g_fee_job.height);
            last_stats = now;
        }
        if (now - last_status >= STATUS_MS) {
            print_status(&cfg);
            last_status = now;
        }
        usleep(2000);
    }

    g_run = 0;
    for (int i = 0; i < cfg.threads; i++) pthread_join(th[i], NULL);
    free(th);
    conn_close(&g_mainc);
    conn_close(&g_feec);
    if (g_ctx) SSL_CTX_free(g_ctx);
    return 0;
}