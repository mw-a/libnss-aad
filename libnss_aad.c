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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define USER_FIELD "mailNickname"

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
        printf("not enough memory (realloc returned NULL)\n");
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
        fprintf(stderr, "libsodium could not be initialized\n");
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
        fprintf(stderr, "failed to allocate memory for string\n");
        return NULL;
    }

    chars[0] = '\0';

    char *endptr = chars;

    char *passwd = (char *) malloc((length + 1) * sizeof(char));

    if (passwd == NULL) {
        fprintf(stderr, "failed to allocate memory for string\n");
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
        printf("Can't open /dev/urandom\n");
        return NULL;
    }

    if (read(fd, entropy, sizeof(entropy)) != sizeof(entropy)) {
        printf("Not enough entropy\n");
        return NULL;
    }

    close(fd);

    return crypt(passwd,
                 crypt_gensalt("$2a$", 12, entropy, sizeof(entropy)));
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

    if (debug)
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl_handle);

    /* check for errors */
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() %s failed: %s\n",
                endpoint, curl_easy_strerror(res));
    } else {
        token_data = json_loads(resp.data, 0, &error);

        if (!token_data) {
            fprintf(stderr, "json_loads() failed: %s\n", error.text);
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

static int verify_user(json_t * auth_token, const char *domain,
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
    sds ext_id = NULL;
    struct response resp;
    struct curl_slist *headers = NULL;
    const char *user_field;

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

    if (debug)
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() %s failed: %s\n",
                endpoint_apps, curl_easy_strerror(res));
        goto out;
    }

    app_data = json_loads(resp.data, 0, &error);
    if (!app_data) {
        fprintf(stderr, "json_loads() failed: %s\n", error.text);
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

        fprintf(stderr, "schema extension app not found: %s\n", message);
        printf(resp.data);
        goto out;
    }

    ext_id_uuid = json_string_value(ext_id_json);
    if (!ext_id_uuid) {
        fprintf(stderr, "wrong data type retrieving schema extension app ID\n");
        goto out;
    }

    curl_easy_cleanup(curl_handle);
    free(resp.data);

    int count;
    sds *tokens = sdssplitlen(ext_id_uuid, strlen(ext_id_uuid), "-", 1, &count);
    if (!tokens) {
        fprintf(stderr, "out of memory splitting schema extension app ID\n");
        goto out;
    }

    ext_id = sdsjoinsds(tokens, count, "", 0);
    sdsfreesplitres(tokens, count);
    json_decref(app_data);
    app_data = NULL;

    if (!ext_id_uuid) {
        fprintf(stderr, "out of memory retrieving schema extension app ID\n");
        goto out;
    }

    resp.data = malloc(1);
    resp.size = 0;

    /* https://graph.microsoft.com/v1.0/users/<username>@<domain> */
    endpoint = sdscat(endpoint, name);
    endpoint = sdscat(endpoint, "@");
    endpoint = sdscat(endpoint, domain);
    endpoint = sdscat(endpoint, "?$select=extension_");
    endpoint = sdscat(endpoint, ext_id);
    endpoint = sdscat(endpoint, "_uidNumber,extension_");
    endpoint = sdscat(endpoint, ext_id);
    endpoint = sdscat(endpoint, "_gidNumber");

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
                     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);

    if (debug)
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() %s failed: %s\n",
                endpoint, curl_easy_strerror(res));
        goto out;
    }

    user_data = json_loads(resp.data, 0, &error);
    if (!user_data) {
        fprintf(stderr, "json_loads() failed: %s\n", error.text);
        goto out;
    }

    if (json_object_get(user_data, "odata.error")) {
        fprintf(stderr, "returned odata.error\n");
        goto out;
    }

    printf("resp.data: %s\n", resp.data);

out:
    json_decref(user_data);
    sdsfree(ext_id);
    json_decref(app_data);
    curl_easy_cleanup(curl_handle);
    curl_slist_free_all(headers);
    sdsfree(auth_header);
    sdsfree(endpoint);
    free(resp.data);

    user_field = json_string_value(json_object_get(user_data, USER_FIELD));
    return (user_field
            && strcmp(user_field,
                      name) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
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
    const char *client_id, *client_secret, *domain, *shell;
    json_t *config, *client, *shell_cfg, *token, *user_cfg;
    json_error_t error;
    int ret = 0, user_id = MIN_UID;
    sds home_dir = sdsnew("/home/");
    struct group *group;
    struct passwd *user;

    (void) (errnop);            /* unused-parameter */

    config = json_load_file(CONF_FILE, 0, &error);
    if (!config) {
        fprintf(stderr, "error in config on line %d: %s\n", error.line,
                error.text);
        return NSS_STATUS_NOTFOUND;
    }

    if (json_object_get(config, "debug"))
        if (strcmp
            (json_string_value(json_object_get(config, "debug")),
             "true") == 0)
            debug = true;

    if (json_object_get(config, "client")) {
        client = json_object_get(config, "client");
    } else {
        fprintf(stderr, "error with Client in JSON\n");
        return ret;
    }

    if (json_object_get(client, "id")) {
        client_id = json_string_value(json_object_get(client, "id"));
    } else {
        fprintf(stderr, "error with Client ID in JSON\n");
        return ret;
    }

    if (json_object_get(client, "secret")) {
        client_secret =
            json_string_value(json_object_get(client, "secret"));
    } else {
        fprintf(stderr, "error with Client Secret in JSON\n");
        return ret;
    }

    if (json_object_get(config, "domain")) {
        domain = json_string_value(json_object_get(config, "domain"));
    } else {
        fprintf(stderr, "error with Domain in JSON\n");
        return ret;
    }

    if (json_object_get(config, "user")) {
        user_cfg = json_object_get(config, "user");
    } else {
        fprintf(stderr, "error with User in JSON\n");
        return ret;
    }

    user = getpwuid(user_id);

    if (json_object_get(user_cfg, "group")) {
        group =
            getgrnam(json_string_value
                     (json_object_get(user_cfg, "group")));
    } else {
        fprintf(stderr, "error with Group in JSON\n");
        return ret;
    }

    if (json_object_get(user_cfg, "shell")) {
        shell_cfg = json_object_get(user_cfg, "shell");
    }

    shell = (shell_cfg) ? json_string_value(shell_cfg) : sdsnew(SHELL);
    if (!shell) {
        fprintf(stderr, "error with Shell in JSON\n");
        return ret;
    }

    home_dir = sdscat(home_dir, name);
    if (!home_dir) {
        fprintf(stderr, "error with HOME directory\n");
        return ret;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    token = get_oauth2_token(client_id, client_secret, domain, debug);
    if (!token) {
        fprintf(stderr, "failed to acquire token\n");
        return NSS_STATUS_UNAVAIL;
    }

    ret = verify_user(token, domain, name, debug);

    curl_global_cleanup();

    if (!ret) {
        if ((p->pw_name =
             get_static(&buffer, &buflen, strlen(name) + 1)) == NULL)
            return NSS_STATUS_TRYAGAIN;

        strcpy(p->pw_name, name);

        if ((p->pw_passwd =
             get_static(&buffer, &buflen, strlen("x") + 1)) == NULL)
            return NSS_STATUS_TRYAGAIN;

        strcpy(p->pw_passwd, "x");

        while (user != NULL) {
            user = getpwuid(++user_id);
        }
        p->pw_uid = user_id;

        p->pw_gid = (group) ? group->gr_gid : MIN_GID;

        if ((p->pw_gecos =
             get_static(&buffer, &buflen, strlen("\0") + 1)) == NULL)
            return NSS_STATUS_TRYAGAIN;

        strcpy(p->pw_gecos, "\0");

        if ((p->pw_dir =
             get_static(&buffer, &buflen, strlen(home_dir) + 1)) == NULL)
            return NSS_STATUS_TRYAGAIN;

        strcpy(p->pw_dir, home_dir);

        if ((p->pw_shell =
             get_static(&buffer, &buflen, strlen(shell) + 1)) == NULL)
            return NSS_STATUS_TRYAGAIN;

        strcpy(p->pw_shell, shell);

        write_entry(PASSWD_FILE, p);

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_TRYAGAIN;
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

    write_entry(SHADOW_FILE, s);

    s->sp_lstchg = 13571;
    s->sp_min = 0;
    s->sp_max = 99999;
    s->sp_warn = 7;

    return NSS_STATUS_SUCCESS;
}
