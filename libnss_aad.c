#include <crypt.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <jansson.h>
#include <nss.h>
#include <pwd.h>
#include <sds/sds.h>
#include <shadow.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONF_FILE "/etc/libnss-aad.conf"
#define MAX_PASSWD_LENGTH 32
#define MIN_GID 1000
#define MIN_UID 1000
#define PASSWD_FILE "/etc/passwd"
#define RESOURCE_ID "https%3A%2F%2Fgraph.microsoft.com%2F.default"
#define SHADOW_FILE "/etc/shadow"
#define SHELL "/bin/sh"
#define USER_AGENT "libnss_aad/1.0"
#define USER_FIELD "userPrincipalName"

struct charset {
    char const *const c;
    uint32_t const l;
};

struct response {
    char *data;
    size_t size;
};

static size_t response_callback(void *contents, size_t size, size_t nmemb,
                                void *userp)
{
    size_t realsize = size * nmemb;
    struct response *resp = (struct response *) userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (ptr == NULL) {
        /* out of memory! */
        syslog(LOG_ERR, "not enough memory (realloc returned NULL)");
        return 0;
    }

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;

    return realsize;
}

static char *get_static(char **buffer, size_t *buflen, int len)
{
    char *result;

    if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
        return NULL;
    }

    result = *buffer;
    *buffer += len;
    *buflen -= len;

    return result;
}

static char *generate_passwd(void)
{
    if (sodium_init() < 0) {
        syslog(LOG_ERR, "libsodium could not be initialized");
        return NULL;
    }

    uintmax_t const length = MAX_PASSWD_LENGTH;

    struct charset lower = {
        "abcdefghijklmnopqrstuvwxyz",
        (uint32_t) strlen(lower.c)
    };

    struct charset numeric = {
        "0123456789",
        (uint32_t) strlen(numeric.c)
    };

    struct charset special = {
        "!@#$%^&*()-_=+`~[]{}\\|;:'\",.<>/?",
        (uint32_t) strlen(special.c)
    };

    struct charset upper = {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        (uint32_t) strlen(upper.c)
    };

    uint32_t const chars_l = lower.l + numeric.l + special.l + upper.l;

    char *const chars = malloc(chars_l + 1);

    if (chars == NULL) {
        syslog(LOG_ERR, "failed to allocate memory for string");
        return NULL;
    }

    chars[0] = '\0';

    char *endptr = chars;

    char *passwd = (char *) malloc((length + 1) * sizeof(char));

    if (passwd == NULL) {
        syslog(LOG_ERR, "failed to allocate memory for string");
        return NULL;
    }

    memcpy(endptr, lower.c, lower.l);
    endptr += lower.l;

    memcpy(endptr, numeric.c, numeric.l);
    endptr += numeric.l;

    memcpy(endptr, special.c, special.l);
    endptr += special.l;

    memcpy(endptr, upper.c, upper.l);

    for (uintmax_t i = 0; i < length; ++i) {
        passwd[i] = chars[randombytes_uniform(chars_l)];
    }

    passwd[length + 1] = '\0';

    free(chars);

    char entropy[16];
    int fd;

    fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        syslog(LOG_ERR, "Can't open /dev/urandom\n");
        return NULL;
    }

    if (read(fd, entropy, sizeof(entropy)) != sizeof(entropy)) {
        syslog(LOG_ERR, "Not enough entropy\n");
        return NULL;
    }

    close(fd);

    return crypt(passwd,
                 crypt_gensalt("$2a$", 12, entropy, sizeof(entropy)));
}

static int curl_log(CURL *handle, curl_infotype type, char *data, size_t size,
        void *userptr) {
    char *text;
    (void)handle;

    if (type != CURLINFO_TEXT)
        return 0;

    text = malloc(17 /* libnss_aad curl:  */ + size + 1 /* nul */);
    if (text == NULL) {
        syslog(LOG_CRIT, "error allocating memory in curl debug function");
        return CURLE_OK;
    }

    strcpy(text, "libnss_add curl: ");
    memcpy(text + 17, data, size);
    text[6 + size] = '\0';

    syslog(LOG_DEBUG, text);
    free(text);
    return CURLE_OK;
}

static json_t *get_oauth2_token(const char *client_id,
                                const char *client_secret,
                                const char *domain, bool debug)
{
    CURL *curl_handle;
    CURLcode res;
    json_t *token_data = NULL, *token;
    json_error_t error;
    struct response resp;

    resp.data = malloc(1);
    resp.size = 0;

    /* https://login.microsoftonline.com/<domain>/oauth2/token */
    sds endpoint = sdsnew("https://login.microsoftonline.com/");
    endpoint = sdscat(endpoint, domain);
    endpoint = sdscat(endpoint, "/oauth2/v2.0/token");

    sds post_body = sdsnew("grant_type=client_credentials&client_secret=");
    post_body = sdscat(post_body, client_secret);
    post_body = sdscat(post_body, "&client_id=");
    post_body = sdscat(post_body, client_id);
    post_body = sdscat(post_body, "&scope=");
    post_body = sdscat(post_body, RESOURCE_ID);

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
                     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);

    if (debug) {
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, curl_log);
    }

    res = curl_easy_perform(curl_handle);

    /* check for errors */
    if (res != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_perform() %s failed: %s",
                endpoint, curl_easy_strerror(res));
    } else {
        token_data = json_loads(resp.data, 0, &error);

        if (!token_data) {
            syslog(LOG_ERR, "json_loads() failed: %s", error.text);
            return NULL;
        }
    }

    curl_easy_cleanup(curl_handle);
    sdsfree(endpoint);
    sdsfree(post_body);
    free(resp.data);

    token = json_object_get(token_data, "access_token");
    return (token) ? token : NULL;
}

static json_t *lookup_user(json_t * auth_token, const char *domain,
        const char *name, bool debug)
{
    CURL *curl_handle;
    CURLcode res;
    json_t *user_data = NULL, *app_data = NULL, *ext_id_json;
    json_error_t error;
    sds auth_header = sdsnew("Authorization: Bearer ");
    sds endpoint = sdsnew("https://graph.microsoft.com/v1.0/users/");
    sds endpoint_apps = "https://graph.microsoft.com/v1.0/applications?$select=appId&$filter=displayname%20eq%20'Tenant%20Schema%20Extension%20App'";
    const char *ext_id_uuid;
    sds ext_id = NULL, uidnumber_field = NULL, gidnumber_field = NULL,
        gecos_field = NULL, homedir_field = NULL, shell_field = NULL;
    json_t *uidnumber_json, *gidnumber_json, *gecos_json, *homedir_json, *shell_json;
    struct response resp;
    struct curl_slist *headers = NULL;

    resp.data = malloc(1);
    resp.size = 0;

    auth_header = sdscat(auth_header, json_string_value(auth_token));
    headers = curl_slist_append(headers, auth_header);

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint_apps);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
                     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);

    if (debug) {
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, curl_log);
    }

    res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_perform() %s failed: %s",
                endpoint_apps, curl_easy_strerror(res));
        goto out;
    }

    app_data = json_loads(resp.data, 0, &error);
    if (!app_data) {
        syslog(LOG_ERR, "json_loads() failed: %s", error.text);
        goto out;
    }

    ext_id_json = json_object_get(app_data, "value");
    if (json_array_size(ext_id_json) == 1)
        ext_id_json = json_array_get(ext_id_json, 0);
    if (ext_id_json)
        ext_id_json = json_object_get(ext_id_json, "appId");
    if (!ext_id_json) {
        json_t *error_json = json_object_get(app_data, "error");
        const char *message = "unknown error";

        if (error_json)
            error_json = json_object_get(error_json, "message");
        if (error_json)
            message = json_string_value(error_json);

        syslog(LOG_ERR, "schema extension app not found: %s", message);
        goto out;
    }

    ext_id_uuid = json_string_value(ext_id_json);
    if (!ext_id_uuid) {
        syslog(LOG_ERR, "wrong data type retrieving schema extension app ID");
        goto out;
    }

    curl_easy_cleanup(curl_handle);
    free(resp.data);

    int count;
    sds *tokens = sdssplitlen(ext_id_uuid, strlen(ext_id_uuid), "-", 1, &count);
    if (!tokens) {
        syslog(LOG_ERR, "out of memory splitting schema extension app ID");
        goto out;
    }

    ext_id = sdsjoinsds(tokens, count, "", 0);
    sdsfreesplitres(tokens, count);
    json_decref(app_data);
    app_data = NULL;

    if (!ext_id_uuid) {
        syslog(LOG_ERR, "out of memory retrieving schema extension app ID");
        goto out;
    }

    resp.data = malloc(1);
    resp.size = 0;

    uidnumber_field = sdsnew("extension_");
    uidnumber_field = sdscat(uidnumber_field, ext_id);
    uidnumber_field = sdscat(uidnumber_field, "_uidNumber");

    gidnumber_field = sdsnew("extension_");
    gidnumber_field = sdscat(gidnumber_field, ext_id);
    gidnumber_field = sdscat(gidnumber_field, "_gidNumber");

    gecos_field = sdsnew("extension_");
    gecos_field = sdscat(gecos_field, ext_id);
    gecos_field = sdscat(gecos_field, "_gecos");

    homedir_field = sdsnew("extension_");
    homedir_field = sdscat(homedir_field, ext_id);
    homedir_field = sdscat(homedir_field, "_unixHomeDirectory");

    shell_field = sdsnew("extension_");
    shell_field = sdscat(shell_field, ext_id);
    shell_field = sdscat(shell_field, "_loginShell");

    /* https://graph.microsoft.com/v1.0/users/<username>@<domain> */
    endpoint = sdscat(endpoint, name);
    endpoint = sdscat(endpoint, "@");
    endpoint = sdscat(endpoint, domain);
    endpoint = sdscat(endpoint, "?$select=displayName," USER_FIELD ",");
    endpoint = sdscat(endpoint, uidnumber_field);
    endpoint = sdscat(endpoint, ",");
    endpoint = sdscat(endpoint, gidnumber_field);
    endpoint = sdscat(endpoint, ",");
    endpoint = sdscat(endpoint, gecos_field);
    endpoint = sdscat(endpoint, ",");
    endpoint = sdscat(endpoint, homedir_field);
    endpoint = sdscat(endpoint, ",");
    endpoint = sdscat(endpoint, shell_field);

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
                     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);

    if (debug) {
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, curl_log);
    }

    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_perform() %s failed: %s",
                endpoint, curl_easy_strerror(res));
        goto out;
    }

    user_data = json_loads(resp.data, 0, &error);
    if (!user_data) {
        syslog(LOG_ERR, "json_loads() failed: %s", error.text);
        goto out;
    }

    /* link extension attributes with well-known internal names */
    uidnumber_json = json_object_get(user_data, uidnumber_field);
    gidnumber_json = json_object_get(user_data, gidnumber_field);
    if (uidnumber_json && gidnumber_json) {
        json_object_set(user_data, "uidNumber", uidnumber_json);
        json_object_set(user_data, "gidNumber", gidnumber_json);
    } else {
        json_t *error_json = json_object_get(app_data, "error");
        const char *message = "unknown error";

        if (error_json)
            error_json = json_object_get(error_json, "message");
        if (error_json)
            message = json_string_value(error_json);

        syslog(LOG_ERR, "error retrieving user data: %s", message);
        json_decref(user_data);
        user_data = NULL;
        goto out;
    }

    gecos_json = json_object_get(user_data, gecos_field);
    if (gecos_json)
        json_object_set(user_data, "gecos", gecos_json);

    homedir_json = json_object_get(user_data, homedir_field);
    if (homedir_json)
        json_object_set(user_data, "homedir", homedir_json);

    shell_json = json_object_get(user_data, shell_field);
    if (shell_json)
        json_object_set(user_data, "shell", shell_json);
out:
    sdsfree(uidnumber_field);
    sdsfree(gidnumber_field);
    sdsfree(gecos_field);
    sdsfree(homedir_field);
    sdsfree(shell_field);
    sdsfree(ext_id);
    json_decref(app_data);
    curl_easy_cleanup(curl_handle);
    curl_slist_free_all(headers);
    sdsfree(auth_header);
    sdsfree(endpoint);
    free(resp.data);

    return user_data;
}

static int write_entry(const char *fp, void *userp)
{
    int ret = EXIT_FAILURE;
    FILE *fd = fopen(fp, "a");
    if (fd) {
        fseek(fd, 0, SEEK_END);
        if (strcmp(fp, PASSWD_FILE) == 0) {
            struct passwd *p = (struct passwd *) userp;
            ret = putpwent(p, fd);
        }

        if (strcmp(fp, SHADOW_FILE) == 0) {
            struct spwd *s = (struct spwd *) userp;
            ret = putspent(s, fd);
        }
        fclose(fd);
    }
    return ret;
}

enum nss_status _nss_aad_getpwnam_r(const char *name, struct passwd *p,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    bool debug = false;
    const char *client_id, *client_secret, *domain, *group_name;
    json_t *config = NULL, *debug_json, *client, *client_id_json,
           *client_secret_json, *domain_json, *group_json, *shell_cfg, *token,
           *user_cfg;
    json_t *user_data = NULL, *uidnumber_json, *gidnumber_json, *gecos_json,
           *homedir_json, *shell_json;
    const char *gecos, *homedir, *shell;
    json_error_t error;
    enum nss_status ret = NSS_STATUS_NOTFOUND;

    /* permanent error */
    *errnop = 0;

    config = json_load_file(CONF_FILE, 0, &error);
    if (!config) {
        syslog(LOG_ERR, "error in config on line %d: %s", error.line,
                error.text);
        goto out;
    }

    debug_json = json_object_get(config, "debug");
    if (debug_json && strcmp(json_string_value(debug_json), "true") == 0)
        debug = true;

    client = json_object_get(config, "client");
    if (!client) {
        syslog(LOG_ERR, "error with Client in JSON");
        goto out;
    }

    client_id_json = json_object_get(client, "id");
    if (!client_id_json) {
        syslog(LOG_ERR, "error with Client ID in JSON");
        goto out;
    }

    client_id = json_string_value(client_id_json);

    client_secret_json = json_object_get(client, "secret");
    if (!client_secret_json) {
        syslog(LOG_ERR, "error with Client Secret in JSON");
        goto out;
    }

    client_secret = json_string_value(client_secret_json);

    domain_json = json_object_get(config, "domain");
    if (!domain_json) {
        syslog(LOG_ERR, "error with Domain in JSON");
        goto out;
    }

    domain = json_string_value(domain_json);

    user_cfg = json_object_get(config, "user");
    if (!user_cfg) {
        syslog(LOG_ERR, "error with User in JSON");
        goto out;
    }

    group_json = json_object_get(user_cfg, "group");
    if (!group_json) {
        syslog(LOG_ERR, "error with Group in JSON");
        return ret;
    }

    group_name = json_string_value(group_json);

    shell_cfg = json_object_get(user_cfg, "shell");
    if (!shell_cfg) {
        syslog(LOG_ERR, "error with Shell in JSON");
        return ret;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    /* from here on out errors are transient */
    ret = NSS_STATUS_TRYAGAIN;
    *errnop = EAGAIN;

    token = get_oauth2_token(client_id, client_secret, domain, debug);
    if (!token) {
        syslog(LOG_ERR, "failed to acquire token");
        goto out;
    }

    user_data = lookup_user(token, domain, name, debug);

    curl_global_cleanup();

    if (!user_data) {
        goto out;
    }

    if ((p->pw_name =
         get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
        *errnop = ERANGE;
        goto out;
    }

    strcpy(p->pw_name, name);

    if ((p->pw_passwd =
         get_static(&buffer, &buflen, strlen("x") + 1)) == NULL) {
        *errnop = ERANGE;
        goto out;
    }

    strcpy(p->pw_passwd, "x");

    uidnumber_json = json_object_get(user_data, "uidNumber");
    if (!uidnumber_json) {
        syslog(LOG_ERR, "uid number missing");
        goto out;
    }

    p->pw_uid = json_integer_value(uidnumber_json);
    if (p->pw_uid == 0) {
        syslog(LOG_ERR, "uid number not integer");
        goto out;
    }

    gidnumber_json = json_object_get(user_data, "gidNumber");
    if (gidnumber_json) {
        p->pw_gid = json_integer_value(gidnumber_json);
        if (p->pw_gid == 0) {
            syslog(LOG_ERR, "gid number not integer");
            goto out;
        }
    } else {
        struct group *group = getgrnam(group_name);
        if (!group) {
            syslog(LOG_ERR, "group %s not found", group_name);
            goto out;
        }

        p->pw_gid = group->gr_gid;
    }

    gecos_json = json_object_get(user_data, "gecos");
    if (!gecos_json) {
        gecos_json = json_object_get(user_data, "displayName");
    }
    if (!gecos_json) {
        syslog(LOG_ERR, "gecos missing");
        goto out;
    }

    gecos = json_string_value(gecos_json);
    if (!gecos_json) {
        syslog(LOG_ERR, "gecos not string");
        goto out;
    }

    if ((p->pw_gecos =
         get_static(&buffer, &buflen, strlen(gecos) + 1)) == NULL) {
        *errnop = ERANGE;
        goto out;
    }

    strcpy(p->pw_gecos, gecos);

    homedir_json = json_object_get(user_data, "homedir");
    if (homedir_json) {
        homedir = json_string_value(homedir_json);
        if (!homedir_json) {
            syslog(LOG_ERR, "homedir not string");
            goto out;
        }

        if ((p->pw_dir =
            get_static(&buffer, &buflen, strlen(homedir) + 1)) == NULL) {
            *errnop = ERANGE;
            goto out;
        }

        strcpy(p->pw_dir, homedir);
    } else {
        if ((p->pw_dir =
            get_static(&buffer, &buflen, strlen(name) + 6 /* /home/ */ + 1)) == NULL) {
            *errnop = ERANGE;
            goto out;
        }

        strcpy(p->pw_dir, "/home/");
        strcat(p->pw_dir, name);
    }

    shell_json = json_object_get(user_data, "shell");
    if (shell_json) {
        shell = json_string_value(shell_json);
        if (!shell_json) {
            syslog(LOG_ERR, "shell not string");
            goto out;
        }
    } else {
        if (shell_cfg) {
            shell = json_string_value(shell_cfg);
        } else {
            shell = SHELL;
        }
    }

    if ((p->pw_shell =
         get_static(&buffer, &buflen, strlen(shell) + 1)) == NULL) {
        *errnop = ERANGE;
        goto out;
    }

    strcpy(p->pw_shell, shell);

    //write_entry(PASSWD_FILE, p);
    ret = NSS_STATUS_SUCCESS;
    *errnop = 0;

out:
    json_decref(config);
    json_decref(user_data);

    return ret;
}

enum nss_status _nss_aad_getspnam_r(const char *name, struct spwd *s,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    (void) (errnop);            /* unused-parameter */

    /* If out of memory */
    if ((s->sp_namp =
         get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(s->sp_namp, name);

    if ((s->sp_pwdp =
         get_static(&buffer, &buflen, MAX_PASSWD_LENGTH + 1)) == NULL) {
        return NSS_STATUS_TRYAGAIN;
    }

    char *passwd = generate_passwd();
    if (passwd == NULL)
        return NSS_STATUS_TRYAGAIN;

    strcpy(s->sp_pwdp, passwd);

    //write_entry(SHADOW_FILE, s);

    s->sp_lstchg = 13571;
    s->sp_min = 0;
    s->sp_max = 99999;
    s->sp_warn = 7;

    return NSS_STATUS_SUCCESS;
}
