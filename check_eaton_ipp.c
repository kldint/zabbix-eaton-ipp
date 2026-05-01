#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cjson/cJSON.h>

static char g_url[256]      = "";
static char g_username[256] = "";
static char g_passwd[256]   = "";

/* ── HTTP buffer ─────────────────────────────────────────────────────────── */

typedef struct { char *data; size_t size; } Buf;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, Buf *b) {
    size_t n = size * nmemb;
    b->data = realloc(b->data, b->size + n + 1);
    memcpy(b->data + b->size, ptr, n);
    b->size += n;
    b->data[b->size] = '\0';
    return n;
}

/* ── Config ──────────────────────────────────────────────────────────────── */

static void load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Cannot open config: %s\n", path); exit(1); }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;
        val[strcspn(val, "\r\n")] = '\0';
        if      (!strcmp(line, "url"))      strncpy(g_url,      val, sizeof(g_url)      - 1);
        else if (!strcmp(line, "username")) strncpy(g_username, val, sizeof(g_username) - 1);
        else if (!strcmp(line, "passwd"))   strncpy(g_passwd,   val, sizeof(g_passwd)   - 1);
    }
    fclose(f);
}

/* ── Crypto ──────────────────────────────────────────────────────────────── */

static void sha1_hex(const void *data, size_t len, char out[41]) {
    unsigned char h[SHA_DIGEST_LENGTH];
    SHA1(data, len, h);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(out + i * 2, "%02x", h[i]);
    out[40] = '\0';
}

/* encodePassword = HMAC-SHA1(key=sha1_hex(passwd), data=challenge)
   Matches JS: HMAC.encode(SHA1.encode(passwd), challenge) */
static void encode_password(const char *passwd, const char *challenge, char out[41]) {
    char key[41];
    sha1_hex(passwd, strlen(passwd), key);
    unsigned char h[SHA_DIGEST_LENGTH];
    unsigned int hlen;
    HMAC(EVP_sha1(), key, (int)strlen(key),
         (const unsigned char *)challenge, strlen(challenge), h, &hlen);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(out + i * 2, "%02x", h[i]);
    out[40] = '\0';
}

/* ── HTTP ────────────────────────────────────────────────────────────────── */

static char *http_post(const char *url, const char *post, const char *cookies) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    Buf buf = { malloc(1), 0 };
    buf.data[0] = '\0';

    curl_easy_setopt(c, CURLOPT_URL,           url);
    curl_easy_setopt(c, CURLOPT_POST,          1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS,    post ? post : "");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     &buf);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,       5L);
    if (cookies) curl_easy_setopt(c, CURLOPT_COOKIE, cookies);

    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK || code < 200 || code >= 300) { free(buf.data); return NULL; }
    return buf.data;
}

/* ── IPM API ─────────────────────────────────────────────────────────────── */

static char *get_challenge(void) {
    char ep[512];
    snprintf(ep, sizeof(ep),
             "http://%s:4679/server/user_srv.js?action=queryLoginChallenge", g_url);
    char *resp = http_post(ep, NULL, NULL);
    if (!resp) return NULL;
    cJSON *j = cJSON_Parse(resp); free(resp);
    if (!j) return NULL;
    cJSON *ch = cJSON_GetObjectItem(j, "challenge");
    char *r = ch ? strdup(ch->valuestring) : NULL;
    cJSON_Delete(j);
    return r;
}

static char *get_token(const char *challenge) {
    char hash[41];
    encode_password(g_passwd, challenge, hash);
    char post[512];
    snprintf(post, sizeof(post), "login=%s&password=%s", g_username, hash);
    char ep[512];
    snprintf(ep, sizeof(ep),
             "http://%s:4679/server/user_srv.js?action=loginUser", g_url);
    char *resp = http_post(ep, post, NULL);
    if (!resp) return NULL;
    cJSON *j = cJSON_Parse(resp); free(resp);
    if (!j) return NULL;
    cJSON *sid = cJSON_GetObjectItem(j, "sessionID");
    char *r = sid ? strdup(sid->valuestring) : NULL;
    cJSON_Delete(j);
    return r;
}

static char *get_ups_data(const char *sn, const char *token) {
    char post[1024];
    snprintf(post, sizeof(post),
             "nodes=%%5B%%22%s%%22%%5D&sessionID=%s", sn, token);
    char cookies[512];
    snprintf(cookies, sizeof(cookies),
             "mc2LastLogin=%s;sessionID=%s", g_username, token);
    char ep[512];
    snprintf(ep, sizeof(ep),
             "http://%s:4679/server/data_srv.js?action=loadNodeData", g_url);
    char *resp = http_post(ep, post, cookies);
    if (!resp) return NULL;
    cJSON *j = cJSON_Parse(resp); free(resp);
    if (!j) return NULL;
    cJSON *nd = cJSON_GetObjectItem(j, "nodeData");
    char *r = (nd && nd->child) ? cJSON_PrintUnformatted(nd->child) : NULL;
    cJSON_Delete(j);
    return r;
}

static cJSON *discover_node_list(const char *token) {
    char post[512];
    snprintf(post, sizeof(post),
             "filter=%%5B%%5D&fieldSet=%%5B%%22nodeID%%22%%5D&sessionID=%s", token);
    char cookies[512];
    snprintf(cookies, sizeof(cookies),
             "mc2LastLogin=%s;sessionID=%s", g_username, token);
    char ep[512];
    snprintf(ep, sizeof(ep),
             "http://%s:4679/server/data_srv.js?action=loadNodeList", g_url);
    char *resp = http_post(ep, post, cookies);
    if (!resp) return NULL;
    cJSON *j = cJSON_Parse(resp); free(resp);
    if (!j) return NULL;
    cJSON *nl = cJSON_GetObjectItem(j, "nodeList");
    cJSON *nd = nl ? cJSON_GetObjectItem(nl, "nodeData") : NULL;
    cJSON *r  = nd ? cJSON_Duplicate(nd, 1) : NULL;
    cJSON_Delete(j);
    return r;
}

static void do_logout(const char *token) {
    char post[256];
    snprintf(post, sizeof(post), "sessionID=%s", token);
    char cookies[512];
    snprintf(cookies, sizeof(cookies),
             "mc2LastLogin=%s;sessionID=%s", g_username, token);
    char ep[512];
    snprintf(ep, sizeof(ep),
             "http://%s:4679/server/user_srv.js?action=logoutUser", g_url);
    char *r = http_post(ep, post, cookies);
    free(r);
}

/* ── Commands ────────────────────────────────────────────────────────────── */

static void cmd_get(const char *sn) {
    char *challenge = get_challenge();
    if (!challenge) { fprintf(stderr, "Failed to get challenge\n"); return; }
    char *token = get_token(challenge); free(challenge);
    if (!token) { fprintf(stderr, "Failed to get token\n"); return; }
    char *data = get_ups_data(sn, token);
    do_logout(token); free(token);
    if (data) { puts(data); free(data); }
}

static void cmd_discover(void) {
    char *challenge = get_challenge();
    if (!challenge) { fprintf(stderr, "Failed to get challenge\n"); return; }
    char *token = get_token(challenge); free(challenge);
    if (!token) { fprintf(stderr, "Failed to get token\n"); return; }

    cJSON *nodes = discover_node_list(token);
    cJSON *list  = cJSON_CreateArray();

    if (nodes) {
        /* nodeData is an object: each key is a UPS serial number */
        for (cJSON *n = nodes->child; n; n = n->next) {
            char *raw = get_ups_data(n->string, token);
            if (!raw) continue;
            cJSON *upsdata = cJSON_Parse(raw); free(raw);
            if (!upsdata) continue;
            cJSON *name  = cJSON_GetObjectItem(upsdata, "System.Name");
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "{#UPS_NAME}", name ? name->valuestring : "");
            cJSON_AddStringToObject(entry, "{#UPS_SN}",   n->string);
            cJSON_AddItemToArray(list, entry);
            cJSON_Delete(upsdata);
        }
        cJSON_Delete(nodes);
    }

    cJSON *discovered = cJSON_CreateObject();
    cJSON_AddItemToObject(discovered, "data", list);
    char *out = cJSON_PrintUnformatted(discovered);
    do_logout(token); free(token);
    if (out) { puts(out); free(out); }
    cJSON_Delete(discovered);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config  = NULL;
    const char *command = NULL;
    const char *ups_sn  = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) config = argv[++i];
        else if (!command) command = argv[i];
        else if (!ups_sn)  ups_sn  = argv[i];
    }

    if (!config) {
        fprintf(stderr, "Usage: %s -c <config> get <ups_sn>\n"
                        "       %s -c <config> discover\n", argv[0], argv[0]);
        return 1;
    }

    load_config(config);

    if (!g_url[0] || !g_username[0] || !g_passwd[0]) {
        fprintf(stderr, "Config error: url, username and passwd are required in %s\n", config);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (command && !strcmp(command, "get")) {
        if (!ups_sn) {
            fprintf(stderr, "get requires a UPS serial number\n");
            curl_global_cleanup();
            return 1;
        }
        cmd_get(ups_sn);
    } else {
        cmd_discover();
    }

    curl_global_cleanup();
    return 0;
}
