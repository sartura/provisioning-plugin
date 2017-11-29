#include <stdio.h>
#include "provisioning.h"
#include "adiag_functions.h"
#include "common.h"

const char *YANG_MODEL = "terastream-provisioning";
const char *PLUGIN_NAME = "sysrepo-plugin-dt-provisioning";

/* Mappings of operational nodes to corresponding handler functions. */
/* Functions must not need the plugin context. */
static adiag_node_func_m table_operational[] = {
    {"version", adiag_version},
    {"memory-status", adiag_free_memory},
    {"cpu-usage", adiag_cpu_usage},
    {"version-running-bank", adiag_running_bank},
    {"version-other-bank", adiag_other_bank},
};

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx)
        return;

    struct plugin_ctx *ctx = private_ctx;

    if (ctx->subscription != NULL)
        sr_unsubscribe(session, ctx->subscription);

    if (ctx->startup_session != NULL)
        sr_session_stop(ctx->startup_session);

    if (ctx->startup_connection != NULL)
        sr_disconnect(ctx->startup_connection);

    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
}

static int data_provider_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    size_t n_mappings = ARR_SIZE(table_operational);
    INF("Diagnostics for %s %d", cb_xpath, n_mappings);

    *values_cnt = n_mappings;
    int rc = sr_new_values(*values_cnt, values);
    SR_CHECK_RET(rc, exit, "Couldn't create values %s", sr_strerror(rc));

    for (size_t i = 0; i < *values_cnt; i++) {
        char *node = table_operational[i].node;
        adiag_func func = table_operational[i].op_func;
        INF("\tDiagnostics for: %s", node);

        rc = func(&(*values)[i]);
    }

exit:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    /* sr_subscription_ctx_t *subscription = NULL; */
    int rc = SR_ERR_OK;
    INF("%s for %s", __func__, PLUGIN_NAME);

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "Can't allocate plugin context\n");
        rc = SR_ERR_NOMEM;
        goto exit;
    }
    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->startup_connection);
    SR_CHECK_RET(rc, err_ctx, "Error by sr_connect: %s", sr_strerror(rc));

    INF_MSG("Starting startup session ...");
    rc = sr_session_start(ctx->startup_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->startup_session);
    SR_CHECK_RET(rc, err_conn, "Error by sr_session_start: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to diagnostics");
    rc = sr_dp_get_items_subscribe(
        session, "/terastream-provisioning:hgw-diagnostics", data_provider_cb, *private_ctx, SR_SUBSCR_DEFAULT, &ctx->subscription);
    SR_CHECK_RET(rc, err_ses, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    *private_ctx = ctx;
    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    goto exit;

err_ses:
    sr_session_stop(ctx->startup_session);
err_conn:
    sr_disconnect(ctx->startup_connection);
err_ctx:
    free(ctx);
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
exit:
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
    int status = EXIT_FAILURE;
    INF_MSG("Plugin application mode initialized");

    /* connect to sysrepo */
    sr_conn_ctx_t *connection = NULL;
    INF_MSG("Connecting to sysrepo ...");
    int rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
    SR_CHECK_RET(rc, exit, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    sr_session_ctx_t *session = NULL;
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    SR_CHECK_RET(rc, err_conn, "Error by sr_session_start: %s", sr_strerror(rc));

    void *private_ctx = NULL;
    INF_MSG("Initializing plugin ...");
    rc = sr_plugin_init_cb(session, &private_ctx);
    SR_CHECK_RET(rc, err_ses, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1); /* or do some more useful work... */
    }

    sr_plugin_cleanup_cb(session, private_ctx);

    status = EXIT_SUCCESS;
err_ses:
    sr_session_stop(session);
err_conn:
    sr_disconnect(connection);
exit:
    return status;
}
#endif /* PLUGIN */
