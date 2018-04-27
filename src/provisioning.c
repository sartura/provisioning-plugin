#include <stdio.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "provisioning.h"
#include "common.h"

#define XPATH_VERSION "/terastream-provisioning:hgw-diagnostics/version"
#define XPATH_MEMORY "/terastream-provisioning:hgw-diagnostics/memory-status"
#define XPATH_DISK "/terastream-provisioning:hgw-diagnostics/disk-usage"
#define XPATH_CPU "/terastream-provisioning:hgw-diagnostics/cpu-usage"
#define XPATH_RUNNING_BANK "/terastream-provisioning:hgw-diagnostics/version-running-bank"
#define XPATH_OTHER_BANK "/terastream-provisioning:hgw-diagnostics/version-other-bank"

const char *yang_model = "terastream-provisioning";
const char *PLUGIN_NAME = "sysrepo-plugin-dt-provisioning";

static void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx)
        return;

    ctx_t *ctx = private_ctx;
    if (NULL == ctx) {
        return;
    }
    if (NULL != ctx->sub) {
        sr_unsubscribe(session, ctx->sub);
    }
    free(ctx);
    ctx = NULL;

    DBG_MSG("Plugin cleaned-up successfully");
}

static void version_running_bank_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_current_bank = NULL;
    char *json_string = NULL;
    const char *result_string = NULL;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "current_bank_firmware", &jobj_current_bank);
    if (NULL == jobj_current_bank) {
        goto cleanup;
    }

    result_string = json_object_get_string(jobj_current_bank);
    if (NULL == result_string) {
        DBG_MSG("no current_bank_firmware in json object");
        goto cleanup;
    }

    *ubus_ctx->values_cnt = 1;
    rc = sr_new_val(XPATH_RUNNING_BANK, ubus_ctx->values);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, result_string);

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;
}


static int version_running_bank_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "memory_bank", buf.head, version_running_bank_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object memory_bank\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static void version_other_bank_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_previous_bank = NULL;
    char *json_string = NULL;
    const char *result_string = NULL;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "previous_bank_firmware", &jobj_previous_bank);
    if (NULL == jobj_previous_bank) {
        goto cleanup;
    }

    result_string = json_object_get_string(jobj_previous_bank);
    if (NULL == result_string) {
        DBG_MSG("no previous_bank_firmware in json object");
        goto cleanup;
    }

    *ubus_ctx->values_cnt = 1;
    rc = sr_new_val(XPATH_OTHER_BANK, ubus_ctx->values);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, result_string);

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;
}

static int version_other_bank_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "memory_bank", buf.head, version_other_bank_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object memory_bank\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static void version_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_release = NULL, *jobj_revision = NULL;
    char *json_string = NULL;
    const char *result_string = NULL;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "release", &jobj_release);
    if (NULL == jobj_release) {
        goto cleanup;
    }
    json_object_object_get_ex(jobj_release, "revision", &jobj_revision);
    if (NULL == jobj_revision) {
        goto cleanup;
    }

    result_string = json_object_get_string(jobj_revision);
    if (NULL == result_string) {
        DBG_MSG("no revision in json object");
        goto cleanup;
    }

    *ubus_ctx->values_cnt = 1;
    rc = sr_new_val(XPATH_VERSION, ubus_ctx->values);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, result_string);

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;
}

static int version_cb(const char *cxpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "board", buf.head, version_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object board\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;

}

static void disk_usage_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_filesystem = NULL;
    char *json_string = NULL;
    uint8_t result_value = 0;
    int array_length = 0;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "filesystem", &jobj_filesystem);
    if (NULL == jobj_filesystem) {
        goto cleanup;
    }
    if (json_type_array != json_object_get_type(jobj_filesystem)) {
        DBG_MSG("json not array type");
        goto cleanup;
    }

    array_length = json_object_array_length(jobj_filesystem);
    if (array_length <= 0) {
        DBG_MSG("no elements in filesystem json array");
        goto cleanup;
    }

    for (int i = 0; i < array_length; i++) {
        struct json_object *jobj_element = NULL, *jobj_mounted = NULL;
        jobj_element = json_object_array_get_idx(jobj_filesystem, i);
        if (NULL == jobj_element) {
            continue;
        }
        json_object_object_get_ex(jobj_element, "mounted_on", &jobj_mounted);
        if (NULL == jobj_mounted) {
            continue;
        }

        // check that we are looking at the right partition
        if (strcmp(json_object_get_string(jobj_mounted), "/") == 0) {
            struct json_object *jobj_percentage = NULL;
            json_object_object_get_ex(jobj_element, "use_pre", &jobj_percentage);
            if (NULL == jobj_percentage) {
                WRN_MSG("expected use_pre element");
                break;
            }

            result_value = (uint8_t) json_object_get_int(jobj_percentage);
            *ubus_ctx->values_cnt = 1;
            rc = sr_new_val(XPATH_DISK, ubus_ctx->values);
            CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
            ubus_ctx->values[0]->type = SR_UINT8_T;
            ubus_ctx->values[0]->data.uint8_val = result_value;

            // we found what we were looking for
            break;
        }
    }

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;
}

static int disk_usage_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "fs", buf.head, disk_usage_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object fs\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static void memory_status_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_memory = NULL, *jobj_total = NULL, *jobj_used = NULL;
    char *json_string = NULL;
    uint8_t result_value = 0;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "memoryKB", &jobj_memory);
    if (NULL == jobj_memory) {
        goto cleanup;
    }
    json_object_object_get_ex(jobj_memory, "total", &jobj_total);
    if (NULL == jobj_total) {
        goto cleanup;
    }
    json_object_object_get_ex(jobj_memory, "used", &jobj_used);
    if (NULL == jobj_used) {
        goto cleanup;
    }

    result_value = (uint8_t) ((100 * json_object_get_int(jobj_used)) / json_object_get_int(jobj_total));

    *ubus_ctx->values_cnt = 1;
    rc = sr_new_val(XPATH_MEMORY, ubus_ctx->values);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    ubus_ctx->values[0]->type = SR_UINT8_T;
    ubus_ctx->values[0]->data.uint8_val = result_value;

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;

}
static int memory_status_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "info", buf.head, memory_status_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object info\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static void cpu_usage_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *jobj_parent = NULL, *jobj_system = NULL, *jobj_cpu_per = NULL;
    char *json_string = NULL;
    uint8_t result_value = 0;
    int rc = SR_ERR_OK;

    if (msg) {
        json_string = blobmsg_format_json(msg, true);
        jobj_parent = json_tokener_parse(json_string);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(jobj_parent, "system", &jobj_system);
    if (NULL == jobj_system) {
        goto cleanup;
    }
    json_object_object_get_ex(jobj_system, "cpu_per", &jobj_cpu_per);
    if (NULL == jobj_cpu_per) {
        goto cleanup;
    }

    result_value = (uint8_t) json_object_get_int(jobj_cpu_per);

    *ubus_ctx->values_cnt = 1;
    rc = sr_new_val(XPATH_CPU, ubus_ctx->values);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    ubus_ctx->values[0]->type = SR_UINT8_T;
    ubus_ctx->values[0]->data.uint8_val = result_value;

cleanup:
    if (NULL != jobj_parent) {
        json_object_put(jobj_parent);
    }
    if (NULL != json_string) {
        free(json_string);
    }
    return;
}

static int cpu_usage_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.system\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "info", buf.head, cpu_usage_ubus_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object info\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    /* sr_subscription_ctx_t *subscription = NULL; */
    int rc = SR_ERR_OK;
    INF("%s for %s", __func__, PLUGIN_NAME);

    ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "Can't allocate plugin context\n");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    ctx->sub = NULL;
    ctx->sess = session;
    ctx->yang_model = yang_model;
    *private_ctx = ctx;

    /* Operational data handling. */
    INF_MSG("Subscribing to version");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_VERSION, version_cb, *private_ctx, SR_SUBSCR_DEFAULT, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to disk usage");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_DISK, disk_usage_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    INF_MSG("Subscribing to memory status");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_MEMORY, memory_status_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to cpu usage");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_CPU, cpu_usage_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to running bank");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_RUNNING_BANK, version_running_bank_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to other bank");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, XPATH_OTHER_BANK, version_other_bank_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    return rc;

cleanup:
    ERR("Plugin initialization failed: %s", sr_strerror(rc));
    if (NULL != ctx->sub) {
        sr_unsubscribe(ctx->sess, ctx->sub);
        ctx->sub = NULL;
    }
    return rc;
}

#ifndef PLUGIN

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum)
{
    INF_MSG("Sigint called, exiting...");
    exit_application = 1;
}

int main()
{
    INF_MSG("Plugin application mode initialized");

    /* connect to sysrepo */
    sr_conn_ctx_t *connection = NULL;
    INF_MSG("Connecting to sysrepo ...");
    int rc = sr_connect(yang_model, SR_CONN_DEFAULT, &connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    sr_session_ctx_t *session = NULL;
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    void *private_ctx = NULL;
    INF_MSG("Initializing plugin ...");
    rc = sr_plugin_init_cb(session, &private_ctx);
    CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1); /* or do some more useful work... */
    }

cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
}
#endif /* PLUGIN */
