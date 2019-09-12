#include <stdio.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "provisioning.h"
#include "version.h"
#include <sr_uci.h>

#define XPATH_BASE "/terastream-provisioning:hgw-diagnostics"
#define XPATH_VERSION "/terastream-provisioning:hgw-diagnostics/version"
#define XPATH_MEMORY "/terastream-provisioning:hgw-diagnostics/memory-status"
#define XPATH_DISK "/terastream-provisioning:hgw-diagnostics/disk-usage"
#define XPATH_CPU "/terastream-provisioning:hgw-diagnostics/cpu-usage"
#define XPATH_NAME "/terastream-provisioning:hgw-diagnostics/name"
#define XPATH_HARDWARE "/terastream-provisioning:hgw-diagnostics/hardware"
#define XPATH_MODEL "/terastream-provisioning:hgw-diagnostics/model"
#define XPATH_BOARDID "/terastream-provisioning:hgw-diagnostics/board-id"
#define XPATH_RUNNING_BANK                                                     \
  "/terastream-provisioning:hgw-diagnostics/version-running-bank"
#define XPATH_OTHER_BANK                                                       \
  "/terastream-provisioning:hgw-diagnostics/version-other-bank"

const char *yang_model = "terastream-provisioning";
const char *PLUGIN_NAME = "sysrepo-plugin-dt-provisioning";

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
  INF("Plugin cleanup called, private_ctx is %s available.",
      private_ctx ? "" : "not");
  if (!private_ctx)
    return;

  ctx_t *ctx = private_ctx;
  if (NULL == ctx) {
    return;
  }
  if (NULL != ctx->sub) {
    sr_unsubscribe(ctx->sub);
  }
  free(ctx);
  ctx = NULL;

  DBG_MSG("Plugin cleaned-up successfully");
}

static int ubus_version(struct list_head *list, struct json_object *top,
                        char *ubus_obj_name, char *xpath) {
  struct json_object *jobj_release = NULL;
  int rc = SR_ERR_OK;

  json_object_object_get_ex(top, "release", &jobj_release);
  CHECK_NULL_MSG(jobj_release, &rc, cleanup,
                 "json_object_object_get_ex: failed");

  rc = ubus_string_to_sr(list, jobj_release, ubus_obj_name, xpath);
  CHECK_RET_MSG(rc, cleanup, "ubus_uint8_to_sr: failed");

cleanup:
  return rc;
}

static int ubus_disk_usage(struct list_head *list, struct json_object *top,
                           char *ubus_obj_name, char *xpath) {
  struct json_object *jobj_filesystem = NULL;
  int array_length = 0;
  int rc = SR_ERR_OK;

  json_object_object_get_ex(top, "filesystem", &jobj_filesystem);
  CHECK_NULL_MSG(jobj_filesystem, &rc, cleanup,
                 "json_object_object_get_ex: failed");

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
    CHECK_NULL_MSG(jobj_element, &rc, cleanup,
                   "json_object_array_get_idx: failed");

    json_object_object_get_ex(jobj_element, "mounted_on", &jobj_mounted);
    CHECK_NULL_MSG(jobj_mounted, &rc, cleanup,
                   "json_object_object_get_ex: failed");

    // check that we are looking at the right partition
    if (strcmp(json_object_get_string(jobj_mounted), "/") == 0) {
      rc = ubus_uint8_to_sr(list, jobj_element, ubus_obj_name, xpath);
      CHECK_RET_MSG(rc, cleanup, "ubus_uint8_to_sr: failed");
      break;
    }
  }

cleanup:
  return rc;
}

static int ubus_memory_status(struct list_head *list, struct json_object *top,
                              char *ubus_obj_name, char *xpath) {
  struct json_object *jobj_memory = NULL, *jobj_total = NULL, *jobj_used = NULL;
  sr_value_node_t *list_value = NULL;
  uint8_t result_value = 0;
  int rc = SR_ERR_OK;

  json_object_object_get_ex(top, ubus_obj_name, &jobj_memory);
  CHECK_NULL_MSG(jobj_memory, &rc, cleanup,
                 "json_object_object_get_ex: failed");
  json_object_object_get_ex(jobj_memory, "total", &jobj_total);
  CHECK_NULL_MSG(jobj_total, &rc, cleanup, "json_object_object_get_ex: failed");
  json_object_object_get_ex(jobj_memory, "used", &jobj_used);
  CHECK_NULL_MSG(jobj_used, &rc, cleanup, "json_object_object_get_ex: failed");

  result_value = (uint8_t)((100 * json_object_get_int(jobj_used)) /
                           json_object_get_int(jobj_total));

  list_value = calloc(1, sizeof *list_value);
  CHECK_NULL_MSG(list_value, &rc, cleanup, "calloc: failed");

  list_value->value.xpath = xpath;
  list_value->value.type = SR_UINT8_T;
  list_value->value.data.uint8_val = result_value;
  list_add(&list_value->head, list);

  return rc;
cleanup:
  if (NULL != list_value) {
    free(list_value);
  }
  return rc;
}

void ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
  int rc = SR_ERR_OK;
  ubus_data_t *ctx = req->priv;
  struct json_object *r = NULL;
  char *json_result = NULL;

  CHECK_NULL_MSG(msg, &rc, cleanup, "blob_attr is empty");

  json_result = blobmsg_format_json(msg, true);
  CHECK_NULL_MSG(json_result, &rc, cleanup, "blobmsg_format_json: failed");

  r = json_tokener_parse(json_result);
  CHECK_NULL_MSG(r, &rc, cleanup, "json_tokener_parse: failed");

  ctx->tmp = r;

cleanup:
  if (NULL != json_result) {
    free(json_result);
  }
  return;
}

static void clear_ubus_data(ubus_data_t *ctx) {
  /* clear data out if it exists */
  if (ctx->fs) {
    json_object_put(ctx->fs);
    ctx->fs = NULL;
  }
  if (ctx->info) {
    json_object_put(ctx->info);
    ctx->info = NULL;
  }
  if (ctx->memory_bank) {
    json_object_put(ctx->memory_bank);
    ctx->memory_bank = NULL;
  }
  if (ctx->board) {
    json_object_put(ctx->board);
    ctx->board = NULL;
  }
}

static int get_ubus_data(ubus_data_t *ctx) {
  int rc = SR_ERR_OK;
  uint32_t id = 0;
  struct blob_buf buf = {0};
  int u_rc = UBUS_STATUS_OK;

  struct ubus_context *u_ctx = ubus_connect(NULL);
  CHECK_NULL_MSG(u_ctx, &rc, cleanup, "could not connect to ubus");

  /* ubus call router.system fs */
  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object router.system",
                 u_rc);

  u_rc = ubus_invoke(u_ctx, id, "fs", buf.head, ubus_cb, ctx, 0);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object fs", u_rc);

  ctx->fs = ctx->tmp;
  blob_buf_free(&buf);

  /* ubus call router.system info */
  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object router.system",
                 u_rc);

  u_rc = ubus_invoke(u_ctx, id, "info", buf.head, ubus_cb, ctx, 0);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object info", u_rc);

  ctx->info = ctx->tmp;
  blob_buf_free(&buf);

  /* ubus call router.system memory_bank */
  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object router.system",
                 u_rc);

  u_rc = ubus_invoke(u_ctx, id, "memory_bank", buf.head, ubus_cb, ctx, 0);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object memory_bank", u_rc);

  ctx->memory_bank = ctx->tmp;
  blob_buf_free(&buf);

  /* ubus call system board */
  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "system", &id);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object system", u_rc);

  u_rc = ubus_invoke(u_ctx, id, "board", buf.head, ubus_cb, ctx, 0);
  UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object board", u_rc);

  ctx->board = ctx->tmp;
  blob_buf_free(&buf);

cleanup:
  if (NULL != u_ctx) {
    ubus_free(u_ctx);
    blob_buf_free(&buf);
  }
  return rc;
}

static int sr_oper_data_cb(sr_session_ctx_t *session, const char *module_name,
                           const char *path, const char *request_xpath,
                           uint32_t request_id, struct lyd_node **parent,
                           void *private_data) {
  int rc = SR_ERR_OK;
  ubus_data_t ubus_ctx = {0};
  struct list_head list = LIST_HEAD_INIT(list);
  sr_val_t *values = NULL;
  size_t values_cnt = 0;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  rc = get_ubus_data(&ubus_ctx);
  CHECK_RET_MSG(rc, cleanup, "failed to get ubus data");

  rc = ubus_string_to_sr(&list, ubus_ctx.memory_bank, "previous_bank_firmware",
                         XPATH_OTHER_BANK);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_string_to_sr(&list, ubus_ctx.memory_bank, "current_bank_firmware",
                         XPATH_RUNNING_BANK);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_version(&list, ubus_ctx.board, "revision", XPATH_VERSION);
  CHECK_RET_MSG(rc, cleanup, "ubus_version: failed");

  rc = ubus_disk_usage(&list, ubus_ctx.fs, "use_pre", XPATH_DISK);
  CHECK_RET_MSG(rc, cleanup, "ubus_disk_usage: failed");

  rc = ubus_memory_status(&list, ubus_ctx.info, "memoryKB", XPATH_MEMORY);
  CHECK_RET_MSG(rc, cleanup, "ubus_memory_status: failed");

  struct json_object *jobj_system = NULL;
  json_object_object_get_ex(ubus_ctx.info, "system", &jobj_system);
  CHECK_NULL_MSG(jobj_system, &rc, cleanup,
                 "json_object_object_get_ex: failed");

  rc = ubus_string_to_sr(&list, jobj_system, "name", XPATH_NAME);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_string_to_sr(&list, jobj_system, "boardid", XPATH_BOARDID);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_string_to_sr(&list, jobj_system, "hardware", XPATH_HARDWARE);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_string_to_sr(&list, jobj_system, "model", XPATH_MODEL);
  CHECK_RET_MSG(rc, cleanup, "ubus_string_to_str: failed");

  rc = ubus_uint8_to_sr(&list, jobj_system, "cpu_per", XPATH_CPU);
  CHECK_RET_MSG(rc, cleanup, "ubus_memory_status: failed");

  rc = sr_value_node_copy(&list, &values, &values_cnt);
  CHECK_RET_MSG(rc, cleanup, "sr_value_node_copy: failed");

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, cleanup,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

cleanup:
  sr_value_node_free(&list);
  list_del(&list);
  clear_ubus_data(&ubus_ctx);
  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
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
  rc = sr_oper_get_items_subscribe(ctx->sess, yang_model, XPATH_BASE,
                                   sr_oper_data_cb, *private_ctx,
                                   SR_SUBSCR_DEFAULT, &ctx->sub);
  CHECK_RET(rc, cleanup, "Error by sr_dp_get_items_subscribe: %s",
            sr_strerror(rc));

  DBG_MSG("Plugin initialized successfully");
  return rc;

cleanup:
  ERR("Plugin initialization failed: %s", sr_strerror(rc));
  if (NULL != ctx->sub) {
    sr_unsubscribe(ctx->sub);
    ctx->sub = NULL;
  }
  return rc;
}

#ifndef PLUGIN

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum) {
  INF_MSG("Sigint called, exiting...");
  exit_application = 1;
}

int main() {
  INF_MSG("Plugin application mode initialized");

  ENABLE_LOGGING(SR_LL_DBG);

  /* connect to sysrepo */
  sr_conn_ctx_t *connection = NULL;
  INF_MSG("Connecting to sysrepo ...");
  int rc = sr_connect(SR_CONN_DEFAULT, &connection);
  CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  /* start session */
  sr_session_ctx_t *session = NULL;
  INF_MSG("Starting session ...");
  rc = sr_session_start(connection, SR_DS_RUNNING, &session);
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
