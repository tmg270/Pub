/*
 * gnfp_cminer.c — GNFPHash 1.0.5 CPU miner (Linux / Ubuntu)
 *
 * - Per-thread local counters (flushed every 4096 hashes) for proper scaling
 * - Single-connection 5% fee (time-slice) — no second TLS socket
 * - Official 8-round hash + exact bit target
 * - Proven-rate status
 *
 * Build:
 *   gcc -O3 -march=native -pthread -o gnfp_cminer gnfp_cminer.c -lssl -lcrypto
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
#define DEV_FEE_ADDR        "gnfp19381c4b1d7a9cbae64120f24b16d248ae07c6ff1"
#define DEV_FEE_PERIOD_MS   20000
#define DEV_FEE_WINDOW_MS   1000
#define DEFAULT_HOST        "de.restoreprivacy.online"
#define DEFAULT_PORT        1474
#define LOCAL_FLUSH         4096ull

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
    char address[160];
    char worker[64];
    char user[320];
    char fee_user[320];
    char fee_worker[32];
    int  cpu_cores;
    int  cpu_threads;
    int  smt;
    int  max_threads;
    char platform[32];
    char arch[32];
} cfg_t;

static volatile int g_run = 1;
static int g_sig_hits = 0;
static job_t g_job;
static pthread_mutex_t g_job_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_net_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_q_mu   = PTHREAD_MUTEX_INITIALIZER;

static share_t g_q[SHARE_Q];
static int g_q_head = 0, g_q_tail = 0, g_q_n = 0;
static int g_inflight = 0;
static uint64_t g_inflight_ts[MAX_IN_FLIGHT];
static int g_inflight_fee[MAX_IN_FLIGHT];
static int g_if_n = 0;

static int g_fd = -1;
static SSL *g_ssl = NULL;
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
    for (int i = 0; i < full; i++) {
        if (hash[i] != 0) return 0;
    }
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
        char tag[8];
        int tl = snprintf(tag, sizeof(tag), "%d", r);
        SHA256_Init(&c);
        SHA256_Update(&c, acc, 32);
        SHA256_Update(&c, PERSONAL, 11);
        SHA256_Update(&c, tag, (size_t)tl);
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

static int fee_window_active(void) {
    return (now_ms() % DEV_FEE_PERIOD_MS) < DEV_FEE_WINDOW_MS;
}

static int share_seen(const char *job_id, const char *nonce) {
    for (int i = 0, idx = g_q_head; i < g_q_n; i++, idx = (idx + 1) % SHARE_Q) {
        if (strcmp(g_q[idx].job_id, job_id) == 0 &&
            memcmp(g_q[idx].nonce, nonce, NONCE_HEX) == 0)
            return 1;
    }
    return 0;
}

static int share_push(const char *job_id, const char *nonce, int bits) {
    int ok = 0;
    int fee = fee_window_active();
    pthread_mutex_lock(&g_q_mu);
    if (g_q_n < SHARE_Q && job_id && job_id[0] && nonce && !share_seen(job_id, nonce)) {
        share_t *s = &g_q[g_q_tail];
        snprintf(s->job_id, sizeof(s->job_id), "%s", job_id);
        memcpy(s->nonce, nonce, NONCE_HEX);
        s->nonce[NONCE_HEX] = 0;
        s->bits = bits;
        s->is_fee = fee;
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
    if (g_q_n <= 0) {
        pthread_mutex_unlock(&g_q_mu);
        return 0;
    }
    *out = g_q[g_q_head];
    g_q_head = (g_q_head + 1) % SHARE_Q;
    g_q_n--;
    pthread_mutex_unlock(&g_q_mu);
    return 1;
}

static void share_drop_job_mismatch(const char *live_id) {
    pthread_mutex_lock(&g_q_mu);
    int n = g_q_n, head = g_q_head;
    g_q_head = g_q_tail = g_q_n = 0;
    for (int i = 0; i < n; i++) {
        share_t *s = &g_q[(head + i) % SHARE_Q];
        if (live_id && strcmp(s->job_id, live_id) == 0) {
            g_q[g_q_tail] = *s;
            g_q_tail = (g_q_tail + 1) % SHARE_Q;
            g_q_n++;
        }
    }
    pthread_mutex_unlock(&g_q_mu);
}

static void inflight_release_timeouts(void) {
    uint64_t t = now_ms();
    pthread_mutex_lock(&g_q_mu);
    int w = 0;
    for (int i = 0; i < g_if_n; i++) {
        if (t - g_inflight_ts[i] < INFLIGHT_TO_MS) {
            g_inflight_ts[w] = g_inflight_ts[i];
            g_inflight_fee[w] = g_inflight_fee[i];
            w++;
        } else {
            g_inflight--;
        }
    }
    g_if_n = w;
    if (g_inflight < 0) g_inflight = 0;
    pthread_mutex_unlock(&g_q_mu);
}

static void inflight_add(int is_fee) {
    pthread_mutex_lock(&g_q_mu);
    if (g_if_n < MAX_IN_FLIGHT) {
        g_inflight_ts[g_if_n] = now_ms();
        g_inflight_fee[g_if_n] = is_fee;
        g_if_n++;
        g_inflight++;
    }
    pthread_mutex_unlock(&g_q_mu);
}

static int inflight_ack(int *was_fee) {
    pthread_mutex_lock(&g_q_mu);
    int fee = 0;
    if (g_if_n > 0) {
        fee = g_inflight_fee[0];
        memmove(g_inflight_ts, g_inflight_ts + 1, (size_t)(g_if_n - 1) * sizeof(g_inflight_ts[0]));
        memmove(g_inflight_fee, g_inflight_fee + 1, (size_t)(g_if_n - 1) * sizeof(g_inflight_fee[0]));
        g_if_n--;
        if (g_inflight > 0) g_inflight--;
    }
    pthread_mutex_unlock(&g_q_mu);
    if (was_fee) *was_fee = fee;
    return 1;
}

static int net_send_raw(const char *buf, int n) {
    int off = 0;
    while (off < n && g_run) {
        pthread_mutex_lock(&g_net_mu);
        int w = 0;
        if (g_ssl) {
            w = SSL_write(g_ssl, buf + off, n - off);
            if (w <= 0) {
                int e = SSL_get_error(g_ssl, w);
                pthread_mutex_unlock(&g_net_mu);
                if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
                    usleep(1000);
                    continue;
                }
                return -1;
            }
        } else if (g_fd >= 0) {
            w = (int)write(g_fd, buf + off, (size_t)(n - off));
            if (w < 0) {
                int err = errno;
                pthread_mutex_unlock(&g_net_mu);
                if (err == EAGAIN || err == EWOULDBLOCK) {
                    usleep(1000);
                    continue;
                }
                return -1;
            }
        } else {
            pthread_mutex_unlock(&g_net_mu);
            return -1;
        }
        pthread_mutex_unlock(&g_net_mu);
        off += w;
    }
    return off == n ? 0 : -1;
}

static int net_send_line(const char *json) {
    char buf[2048];
    int n = snprintf(buf, sizeof(buf), "%s\n", json);
    if (n <= 0 || n >= (int)sizeof(buf)) return -1;
    return net_send_raw(buf, n);
}

static void ident_json(char *dst, size_t cap, const cfg_t *cfg, const char *login) {
    snprintf(dst, cap,
             "\"login\":\"%s\",\"threads\":%d,"
             "\"cpuCores\":%d,\"cpuThreads\":%d,\"smt\":%d,\"maxThreads\":%d,"
             "\"platform\":\"%s\",\"arch\":\"%s\","
             "\"client\":\"%s\",\"version\":\"%s\",\"algorithm\":\"%s\"",
             login, cfg->threads, cfg->cpu_cores, cfg->cpu_threads, cfg->smt,
             cfg->max_threads, cfg->platform, cfg->arch,
             CLIENT, VERSION, ALGORITHM);
}

static int send_login(const cfg_t *cfg) {
    char id[768], msg[1024];
    ident_json(id, sizeof(id), cfg, cfg->user);
    snprintf(msg, sizeof(msg),
             "{\"method\":\"login\",%s,\"id\":1,\"jsonrpc\":\"2.0\"}", id);
    return net_send_line(msg);
}

static int send_stats(const cfg_t *cfg, double hashrate, uint64_t hashes, const char *job_id, int height) {
    char id[768], msg[1400];
    ident_json(id, sizeof(id), cfg, cfg->user);
    snprintf(msg, sizeof(msg),
             "{\"method\":\"stats\",%s,\"hashrate\":%.0f,\"hashes\":%llu,"
             "\"jobId\":\"%s\",\"height\":%d,\"jsonrpc\":\"2.0\"}",
             id, hashrate, (unsigned long long)hashes,
             job_id && job_id[0] ? job_id : "", height);
    return net_send_line(msg);
}

static int send_submit(const cfg_t *cfg, const share_t *s) {
    char id[768], msg[1600];
    const char *login = (s->is_fee && cfg->fee_user[0]) ? cfg->fee_user : cfg->user;
    ident_json(id, sizeof(id), cfg, login);
    snprintf(msg, sizeof(msg),
             "{\"method\":\"submit\",%s,\"id\":\"%s\",\"nonce\":\"%s\","
             "\"output\":\"\",\"jobId\":\"%s\",\"jsonrpc\":\"2.0\"}",
             id, s->job_id, s->nonce, s->job_id);
    return net_send_line(msg);
}

/* ========== hash worker with local counters ========== */
static void *hash_worker(void *arg) {
    int tid = (int)(intptr_t)arg;
    uint64_t nonce = (uint64_t)tid + 1;
    char nhex[NONCE_HEX + 1];
    unsigned char dig[32];
    uint64_t seen_gen = 0;
    char pre[HASH_FIELD_MAX + 1];
    size_t pre_len = 0;
    char job_id[128];
    int bits = 14;
    job_id[0] = 0;

    uint64_t local_hashes = 0;
    uint64_t local_found  = 0;
    uint64_t local_found16 = 0;

    while (g_run) {
        pthread_mutex_lock(&g_job_mu);
        uint64_t gen = g_job.gen;
        if (gen != seen_gen) {
            memcpy(pre, g_job.pre, g_job.pre_len);
            pre_len = g_job.pre_len;
            snprintf(job_id, sizeof(job_id), "%s", g_job.job_id);
            bits = g_job.bits;
            seen_gen = gen;
            nonce = (uint64_t)tid + 1;
        }
        pthread_mutex_unlock(&g_job_mu);

        if (!job_id[0] || !pre_len) {
            usleep(2000);
            continue;
        }

        nonce_hex16(nonce, nhex);
        gnfp_hash(pre, pre_len, nhex, dig);

        local_hashes++;

        if (meets_target(dig, bits)) {
            local_found++;
            if (meets_target(dig, bits + 2))
                local_found16++;
            share_push(job_id, nhex, bits);
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
static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int tcp_connect(const char *host, int port) {
    char pbuf[16];
    snprintf(pbuf, sizeof(pbuf), "%d", port);
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
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

static void net_close(void) {
    pthread_mutex_lock(&g_net_mu);
    if (g_ssl) {
        SSL_shutdown(g_ssl);
        SSL_free(g_ssl);
        g_ssl = NULL;
    }
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
    pthread_mutex_unlock(&g_net_mu);
}

static int net_connect(const cfg_t *cfg) {
    net_close();
    int fd = tcp_connect(cfg->host, cfg->port);
    if (fd < 0) {
        fprintf(stderr, "connect failed %s:%d\n", cfg->host, cfg->port);
        return -1;
    }
    if (cfg->tls) {
        if (!g_ctx) {
            SSL_library_init();
            SSL_load_error_strings();
            g_ctx = SSL_CTX_new(TLS_client_method());
            if (!g_ctx) {
                close(fd);
                return -1;
            }
            SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
        }
        SSL *ssl = SSL_new(g_ctx);
        SSL_set_tlsext_host_name(ssl, cfg->host);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "TLS handshake failed\n");
            SSL_free(ssl);
            close(fd);
            return -1;
        }
        g_ssl = ssl;
    }
    set_nonblock(fd);
    g_fd = fd;
    return 0;
}

static int classify_reply(const char *line, char *why, size_t why_cap) {
    char desc[160] = {0};
    json_str(line, "description", desc, sizeof(desc));
    if (!desc[0]) json_str(line, "result", desc, sizeof(desc));
    if (!desc[0]) json_str(line, "error", desc, sizeof(desc));
    for (char *p = desc; *p; p++) *p = (char)tolower((unsigned char)*p);
    long code = 0;
    json_int(line, "code", &code);
    if (strstr(line, "\"formed\":true") || strstr(desc, "block found")) {
        snprintf(why, why_cap, "%s", desc[0] ? desc : "block");
        return 3;
    }
    if (strstr(desc, "accepted") || code == 1) {
        snprintf(why, why_cap, "%s", desc[0] ? desc : "accepted");
        return 1;
    }
    if (strstr(desc, "login")) return 4;
    if (strstr(desc, "stats")) return 5;
    if (desc[0] && (strstr(desc, "reject") || code < 0 || strstr(line, "\"error\""))) {
        snprintf(why, why_cap, "%s", desc);
        return 2;
    }
    if (strstr(line, "\"error\"") && !strstr(line, "\"error\":null")) {
        snprintf(why, why_cap, "%s", desc[0] ? desc : "error");
        return 2;
    }
    return 0;
}

static void apply_job_line(const char *line) {
    job_t j;
    memset(&j, 0, sizeof(j));
    if (!json_str(line, "jobId", j.job_id, sizeof(j.job_id)))
        json_str(line, "id", j.job_id, sizeof(j.job_id));
    if (!json_str(line, "input", j.pre, sizeof(j.pre)))
        json_str(line, "preWork", j.pre, sizeof(j.pre));
    j.pre_len = strlen(j.pre);
    if (j.pre_len > HASH_FIELD_MAX) {
        j.pre_len = HASH_FIELD_MAX;
        j.pre[HASH_FIELD_MAX] = 0;
    }
    long bits = 14, height = 0;
    if (!json_int(line, "difficulty", &bits))
        json_int(line, "bits", &bits);
    if (bits < 1) bits = 1;
    if (bits > 256) bits = 256;
    json_int(line, "height", &height);
    j.bits = (int)bits;
    j.height = (int)height;
    if (!j.job_id[0] || !j.pre_len) return;
    pthread_mutex_lock(&g_job_mu);
    j.gen = g_job.gen + 1;
    g_job = j;
    pthread_mutex_unlock(&g_job_mu);
    g_last_bits = j.bits;
    share_drop_job_mismatch(j.job_id);
    printf("job %s height=%d bits=%d\n", j.job_id, j.height, j.bits);
    fflush(stdout);
}

static void print_status(const cfg_t *cfg, int extra) {
    uint64_t t = now_ms();
    uint64_t dt = t > g_t0_ms ? t - g_t0_ms : 1;
    double sec = dt / 1000.0;
    uint64_t hc = g_hash_calls, sf = g_shares_found, sp = g_shares_pushed;
    uint64_t ss = g_shares_submitted, ac = g_accepts, rj = g_rejects;
    uint64_t imp = g_implausible;
    uint64_t dr = g_shares_dropped, f16 = g_shares_found16, fa = g_fee_accepts;
    int bits = g_last_bits > 0 ? g_last_bits : 14;
    double call = hc / sec;
    double find = sf / sec;
    uint64_t proven_dt = g_first_accept_ms ? (t > g_first_accept_ms ? t - g_first_accept_ms : 1) : dt;
    double proven = (ac * (double)(1ull << bits)) / (proven_dt / 1000.0);
    int qn, inf;
    pthread_mutex_lock(&g_q_mu);
    qn = g_q_n;
    inf = g_inflight;
    pthread_mutex_unlock(&g_q_mu);
    printf(
        "call=%.0f H/s proven=%.0f H/s find=%.2f/s sub=%.2f/s "
        "accepted=%llu rejected=%llu implausible=%llu bits=%d threads=%d "
        "q=%d inflight=%d dropped=%llu fee_acc=%llu found14=%llu found16=%llu\n",
        call, proven, find, ss / sec,
        (unsigned long long)ac, (unsigned long long)rj, (unsigned long long)imp,
        bits, cfg->threads,
        qn, inf, (unsigned long long)dr, (unsigned long long)fa,
        (unsigned long long)sf, (unsigned long long)f16);
    if (extra) {
        printf("  hashes=%llu pushed=%llu submitted=%llu fee_sub=%llu worker=%s fee_worker=%s\n",
               (unsigned long long)hc, (unsigned long long)sp,
               (unsigned long long)ss, (unsigned long long)g_fee_submitted,
               cfg->worker, cfg->fee_worker);
    }
    fflush(stdout);
}

static void flush_submits(const cfg_t *cfg) {
    if (now_ms() < g_backoff_until) return;
    inflight_release_timeouts();
    for (;;) {
        pthread_mutex_lock(&g_q_mu);
        int room = g_inflight < MAX_IN_FLIGHT;
        int have = g_q_n > 0;
        pthread_mutex_unlock(&g_q_mu);
        if (!room || !have) break;
        share_t s;
        if (!share_pop(&s)) break;
        pthread_mutex_lock(&g_job_mu);
        int live = g_job.job_id[0] && strcmp(g_job.job_id, s.job_id) == 0;
        pthread_mutex_unlock(&g_job_mu);
        if (!live) continue;
        if (send_submit(cfg, &s) != 0) {
            share_push(s.job_id, s.nonce, s.bits);
            break;
        }
        inflight_add(s.is_fee);
        __sync_fetch_and_add(&g_shares_submitted, 1);
        if (s.is_fee) __sync_fetch_and_add(&g_fee_submitted, 1);
    }
}

static int handle_line(const cfg_t *cfg, const char *line) {
    if (strstr(line, "\"method\":\"job\"") || strstr(line, "\"input\"") || strstr(line, "\"preWork\"")) {
        if (strstr(line, "\"method\":\"submit\"")) return 0;
        apply_job_line(line);
        return 0;
    }
    char why[160] = {0};
    int k = classify_reply(line, why, sizeof(why));
    if (k == 1 || k == 2 || k == 3) {
        int fee = 0;
        inflight_ack(&fee);
        if (k == 1 || k == 3) {
            __sync_fetch_and_add(&g_accepts, 1);
            if (!g_first_accept_ms) g_first_accept_ms = now_ms();
            if (fee) __sync_fetch_and_add(&g_fee_accepts, 1);
            if (k == 3) {
                __sync_fetch_and_add(&g_blocks, 1);
                printf("BLOCK FOUND %s\n", why);
            } else if (g_accept_print_left > 0) {
                g_accept_print_left--;
                printf("accepted share %s%s\n", why, fee ? " [fee]" : "");
            }
        } else {
            __sync_fetch_and_add(&g_rejects, 1);
            if (why[0] && strstr(why, "implausible")) {
                __sync_fetch_and_add(&g_implausible, 1);
                g_backoff_until = now_ms() + 4000;
                printf("rejected share implausible_rate (total implausible=%llu) — backoff 4s\n",
                       (unsigned long long)g_implausible);
            } else {
                printf("rejected share %s\n", why[0] ? why : "rejected");
            }
        }
        fflush(stdout);
        flush_submits(cfg);
    } else if (k == 4) {
        printf("pool login: %s\n", why[0] ? why : line);
        fflush(stdout);
    }
    return 0;
}

static int pump_reads(const cfg_t *cfg) {
    static char buf[16384];
    static size_t used = 0;
    fd_set rf;
    FD_ZERO(&rf);
    if (g_fd < 0) return -1;
    FD_SET(g_fd, &rf);
    struct timeval tv = {0, 50000};
    int sel = select(g_fd + 1, &rf, NULL, NULL, &tv);
    if (sel < 0 && errno != EINTR) return -1;
    if (sel > 0 && FD_ISSET(g_fd, &rf)) {
        char tmp[4096];
        pthread_mutex_lock(&g_net_mu);
        int n = 0;
        if (g_ssl) n = SSL_read(g_ssl, tmp, (int)sizeof(tmp));
        else n = (int)read(g_fd, tmp, sizeof(tmp));
        pthread_mutex_unlock(&g_net_mu);
        if (n <= 0) {
            if (g_ssl) {
                int e = SSL_get_error(g_ssl, n);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return 0;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (used + (size_t)n >= sizeof(buf)) used = 0;
        memcpy(buf + used, tmp, (size_t)n);
        used += (size_t)n;
        buf[used] = 0;
        char *start = buf;
        char *nl;
        while ((nl = memchr(start, '\n', (size_t)(buf + used - start))) != NULL) {
            *nl = 0;
            if (start[0]) handle_line(cfg, start);
            start = nl + 1;
        }
        size_t left = (size_t)(buf + used - start);
        memmove(buf, start, left);
        used = left;
    }
    return 0;
}

static void session_loop(const cfg_t *cfg) {
    while (g_run) {
        printf("connecting %s://%s:%d\n", cfg->tls ? "tls" : "tcp", cfg->host, cfg->port);
        fflush(stdout);
        if (net_connect(cfg) != 0) {
            sleep(2);
            continue;
        }
        if (send_login(cfg) != 0) {
            net_close();
            sleep(2);
            continue;
        }
        uint64_t last_stats = now_ms();
        uint64_t last_status = now_ms();
        while (g_run) {
            if (pump_reads(cfg) != 0) break;
            flush_submits(cfg);
            uint64_t t = now_ms();
            if (t - last_stats >= STATS_MS) {
                double sec = (t > g_t0_ms ? t - g_t0_ms : 1) / 1000.0;
                char jid[128];
                int height;
                pthread_mutex_lock(&g_job_mu);
                snprintf(jid, sizeof(jid), "%s", g_job.job_id);
                height = g_job.height;
                pthread_mutex_unlock(&g_job_mu);
                send_stats(cfg, g_hash_calls / sec, g_hash_calls, jid, height);
                last_stats = t;
            }
            if (t - last_status >= STATUS_MS) {
                print_status(cfg, 1);
                last_status = t;
            }
        }
        net_close();
        printf("reconnect in 2s\n");
        fflush(stdout);
        if (g_run) sleep(2);
    }
}

static int valid_addr(const char *s) {
    if (strncmp(s, "gnfp1", 5) != 0) return 0;
    size_t n = strlen(s);
    if (n < 25 || n > 85) return 0;
    for (size_t i = 5; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'))) return 0;
    }
    return 1;
}

static int valid_worker(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static void inventory(cfg_t *cfg) {
    long onln = sysconf(_SC_NPROCESSORS_ONLN);
    if (onln < 1) onln = 1;
    cfg->cpu_threads = (int)onln;
    int cores = 0;
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        int phys = -1, core = -1;
        char seen[256][16];
        int ns = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "physical id", 11)) phys = atoi(strchr(line, ':') + 1);
            if (!strncmp(line, "core id", 7)) {
                core = atoi(strchr(line, ':') + 1);
                char key[16];
                snprintf(key, sizeof(key), "%d:%d", phys, core);
                int dup = 0;
                for (int i = 0; i < ns; i++) if (!strcmp(seen[i], key)) dup = 1;
                if (!dup && ns < 256) {
                    snprintf(seen[ns++], 16, "%s", key);
                    cores++;
                }
            }
        }
        fclose(f);
    }
    if (cores < 1) cores = cfg->cpu_threads;
    cfg->cpu_cores = cores;
    cfg->smt = cfg->cpu_cores > 0 ? (cfg->cpu_threads + cfg->cpu_cores - 1) / cfg->cpu_cores : 1;
    if (cfg->smt < 1) cfg->smt = 1;
    cfg->max_threads = cfg->cpu_threads > 256 ? 256 : cfg->cpu_threads;
    snprintf(cfg->platform, sizeof(cfg->platform), "linux");
#if defined(__x86_64__)
    snprintf(cfg->arch, sizeof(cfg->arch), "x64");
#elif defined(__aarch64__)
    snprintf(cfg->arch, sizeof(cfg->arch), "arm64");
#else
    snprintf(cfg->arch, sizeof(cfg->arch), "unknown");
#endif
}

static void setup_fee(cfg_t *cfg) {
    size_t alen = strlen(cfg->address);
    const char *tail = cfg->address + (alen > 6 ? alen - 6 : 0);
    char wshort[9];
    size_t wl = strlen(cfg->worker);
    if (wl > 8) wl = 8;
    memcpy(wshort, cfg->worker, wl);
    wshort[wl] = 0;
    for (size_t i = 0; i < wl; i++) {
        char c = wshort[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '_' || c == '-'))
            wshort[i] = 'x';
    }
    snprintf(cfg->fee_worker, sizeof(cfg->fee_worker), "f%s_%s", tail, wshort);
    if (!valid_worker(cfg->fee_worker))
        snprintf(cfg->fee_worker, sizeof(cfg->fee_worker), "f%s", tail);
    snprintf(cfg->fee_user, sizeof(cfg->fee_user), "%s.%s", DEV_FEE_ADDR, cfg->fee_worker);
}

static int parse_user(cfg_t *cfg, const char *user) {
    char buf[320];
    snprintf(buf, sizeof(buf), "%s", user);
    char *dot = strchr(buf, '.');
    if (dot) {
        *dot = 0;
        snprintf(cfg->address, sizeof(cfg->address), "%s", buf);
        snprintf(cfg->worker, sizeof(cfg->worker), "%s", dot + 1);
    } else {
        snprintf(cfg->address, sizeof(cfg->address), "%s", buf);
        snprintf(cfg->worker, sizeof(cfg->worker), "worker");
    }
    if (!valid_addr(cfg->address)) return 0;
    if (!valid_worker(cfg->worker)) return 0;
    snprintf(cfg->user, sizeof(cfg->user), "%s.%s", cfg->address, cfg->worker);
    setup_fee(cfg);
    return 1;
}

static int selftest(void) {
    const char *pre = "test-prework";
    char nonce[17] = "0000000000000001";
    unsigned char dig[32];
    char hex[65];
    gnfp_hash(pre, strlen(pre), nonce, dig);
    hash_to_hex(dig, hex);
    const char *expect = "986437c40fee8a876e0ca3f1e58b14fa38785a179f57f98ebbb0fb03102bd4eb";
    if (strcmp(hex, expect) != 0) {
        fprintf(stderr, "selftest FAIL got %s want %s\n", hex, expect);
        return 1;
    }
    unsigned char z14[32] = {0};
    z14[1] = 3;
    if (!meets_target(z14, 14) || meets_target(z14, 16)) {
        fprintf(stderr, "selftest FAIL target 14 vs 16\n");
        return 1;
    }
    printf("selftest ok %s\n", hex);
    return 0;
}

static int bench(int seconds, int threads) {
    g_nthreads = threads;
    g_t0_ms = now_ms();
    pthread_mutex_lock(&g_job_mu);
    snprintf(g_job.job_id, sizeof(g_job.job_id), "bench");
    snprintf(g_job.pre, sizeof(g_job.pre), "bench-prework");
    g_job.pre_len = strlen(g_job.pre);
    g_job.bits = 14;
    g_job.gen = 1;
    pthread_mutex_unlock(&g_job_mu);
    pthread_t *th = calloc((size_t)threads, sizeof(*th));
    for (int i = 0; i < threads; i++)
        pthread_create(&th[i], NULL, hash_worker, (void *)(intptr_t)i);
    uint64_t end = now_ms() + (uint64_t)seconds * 1000ull;
    while (now_ms() < end && g_run) usleep(100000);
    g_run = 0;
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
    free(th);
    double sec = (now_ms() - g_t0_ms) / 1000.0;
    printf("bench threads=%d hashes=%llu rate=%.0f H/s finds=%llu finds16=%llu (%.2fs)\n",
           threads, (unsigned long long)g_hash_calls, g_hash_calls / sec,
           (unsigned long long)g_shares_found, (unsigned long long)g_shares_found16, sec);
    return 0;
}

static void usage(void) {
    printf(
        "GNFPHash C miner %s (declared %d%% fee, single connection)\n"
        "  --user gnfp1ADDR.worker   required\n"
        "  --pool host:port          default %s:%d\n"
        "  --threads N               default 8\n"
        "  --notls                   plaintext (local node only)\n"
        "  --selftest\n"
        "  --bench SECONDS\n"
        "Fee %d%% time-sliced on the same connection to %s\n"
        "Local counters flushed every %llu hashes for scaling.\n",
        VERSION, DEV_FEE_PCT, DEFAULT_HOST, DEFAULT_PORT,
        DEV_FEE_PCT, DEV_FEE_ADDR, (unsigned long long)LOCAL_FLUSH);
}

int main(int argc, char **argv) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.host, sizeof(cfg.host), "%s", DEFAULT_HOST);
    cfg.port = DEFAULT_PORT;
    cfg.tls = 1;
    cfg.threads = 8;
    int do_self = 0, do_bench = 0, bench_s = 3;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(); return 0; }
        else if (!strcmp(argv[i], "--selftest")) do_self = 1;
        else if (!strcmp(argv[i], "--bench")) {
            do_bench = 1;
            if (i + 1 < argc && isdigit((unsigned char)argv[i + 1][0])) bench_s = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--notls")) cfg.tls = 0;
        else if (!strcmp(argv[i], "--tls")) cfg.tls = 1;
        else if (!strcmp(argv[i], "--user") && i + 1 < argc) {
            if (!parse_user(&cfg, argv[++i])) {
                fprintf(stderr, "invalid --user (need gnfp1... .worker)\n");
                return 2;
            }
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
        } else if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
            cfg.threads = atoi(argv[++i]);
        }
    }

    inventory(&cfg);
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
    printf("declared fee %d%% (single connection) → %s (worker %s)\n",
           DEV_FEE_PCT, DEV_FEE_ADDR, cfg.fee_worker);
    printf("device cpuCores=%d cpuThreads=%d smt=%d maxThreads=%d %s/%s\n",
           cfg.cpu_cores, cfg.cpu_threads, cfg.smt, cfg.max_threads,
           cfg.platform, cfg.arch);
    fflush(stdout);

    if (selftest() != 0) return 3;

    g_t0_ms = now_ms();
    pthread_t *th = calloc((size_t)cfg.threads, sizeof(*th));
    if (!th) return 1;
    for (int i = 0; i < cfg.threads; i++)
        pthread_create(&th[i], NULL, hash_worker, (void *)(intptr_t)i);

    session_loop(&cfg);

    g_run = 0;
    for (int i = 0; i < cfg.threads; i++) pthread_join(th[i], NULL);
    free(th);
    net_close();
    if (g_ctx) SSL_CTX_free(g_ctx);
    return 0;
}