#include <stdio.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "provisioning.h"
#include "common.h"

const char *yang_model = "terastream-provisioning";
const char *PLUGIN_NAME = "sysrepo-plugin-dt-provisioning";

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
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

static int version_cb(const char *cxpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;

    return rc;
}

static int memory_status_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;

    return rc;
}

static int cpu_usage_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;

    return rc;
}

void version_running_bank_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	ubus_ctx_t *ubus_ctx = req->priv;
	struct json_object *r = NULL, *t = NULL;
	char *json_result = NULL;
	const char *json_string = NULL;
	int rc = SR_ERR_OK;

	if (msg) {
		json_result = blobmsg_format_json(msg, true);
		r = json_tokener_parse(json_result);
	} else {
		goto cleanup;
	}

    json_object_object_get_ex(r, "current_bank_firmware", &t);
    if (NULL == t) {
		goto cleanup;
    }

	json_string = json_object_get_string(t);
	if (NULL == json_string) {
		DBG_MSG("no current_bank_firmware in json object");
		goto cleanup;
	}

    *ubus_ctx->values_cnt = 1;
	rc = sr_new_val("/terastream-provisioning:hgw-diagnostics/version-running-bank", ubus_ctx->values);
	CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
    sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, json_result);

cleanup:
	if (NULL != r) {
		json_object_put(r);
	}
    if (NULL != json_result) {
        free(json_result);
    }
	return;
}


static int version_running_bank_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
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
		ERR("ubus [%d]: no object asterisk\n", u_rc);
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

static int version_other_bank_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    int rc = SR_ERR_OK;

    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
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
        ctx->sess, "/terastream-provisioning:hgw-diagnostics/version", version_cb, *private_ctx, SR_SUBSCR_DEFAULT, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to memory status");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, "/terastream-provisioning:hgw-diagnostics/memory-status", memory_status_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to cpu usage");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, "/terastream-provisioning:hgw-diagnostics/cpu-usage", cpu_usage_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to running bank");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, "/terastream-provisioning:hgw-diagnostics/version-running-bank", version_running_bank_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to other bank");
    rc = sr_dp_get_items_subscribe(
        ctx->sess, "/terastream-provisioning:hgw-diagnostics/version-other-bank", version_other_bank_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
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
