#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <srpo_ubus.h>

#include "transform_data.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define PROVISIONING_YANG_MODEL "terastream-provisioning"
#define PROVISIONING_XPATH_BASE "/" PROVISIONING_YANG_MODEL ":hgw-diagnostics"

typedef char *(*transform_data_cb)(json_object *, const char *, const char *);

typedef struct {
	const char *xpath;
	const char *parent_name;
	const char *name;
	transform_data_cb transform_data;
} provisioning_ubus_json_transform_table_t;

int provisioning_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void provisioning_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int provisioning_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static void provisioning_ubus_info_cb(const char *ubus_json, srpo_ubus_result_values_t *values);
static void provisioning_ubus_board_cb(const char *ubus_json, srpo_ubus_result_values_t *values);
static void provisioning_ubus_fs_cb(const char *ubus_json, srpo_ubus_result_values_t *values);
static void provisioning_ubus_memory_cb(const char *ubus_json, srpo_ubus_result_values_t *values);

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent);

provisioning_ubus_json_transform_table_t provisioning_ubus_board_map[] = {
	{PROVISIONING_XPATH_BASE "/version", "revision", "release", transform_data_subkey_ubus_transform},
};
provisioning_ubus_json_transform_table_t provisioning_ubus_info_map[] = {
	{PROVISIONING_XPATH_BASE "/name", "system", "name", transform_data_subkey_ubus_transform},
	{PROVISIONING_XPATH_BASE "/board-id", "system", "boardid", transform_data_subkey_ubus_transform},
	{PROVISIONING_XPATH_BASE "/hardware", "system", "hardware", transform_data_subkey_ubus_transform},
	{PROVISIONING_XPATH_BASE "/model", "system", "model", transform_data_subkey_ubus_transform},
	{PROVISIONING_XPATH_BASE "/cpu-usage", "system", "cpu_per", transform_data_subkey_ubus_transform},
	{PROVISIONING_XPATH_BASE "/memory-status", NULL, "memoryKB", transform_data_memory_ubus_transform},
};
provisioning_ubus_json_transform_table_t provisioning_ubus_fs_map[] = {
	{PROVISIONING_XPATH_BASE "/disk-usage", "filesystem", "use_pre", transform_data_disk_ubus_transform},
};
provisioning_ubus_json_transform_table_t provisioning_ubus_memory_map[] = {
	{PROVISIONING_XPATH_BASE "/version-other-bank", NULL, "previous_bank_firmware", transform_data_key_ubus_transform},
	{PROVISIONING_XPATH_BASE "/version-running-bank", NULL, "current_bank_firmware", transform_data_key_ubus_transform},
};

static struct {
	const char *module;
	const char *method;
	srpo_ubus_transform_data_cb transform_data;
} provisioning_provider_table[] = {
	{"system", "board", provisioning_ubus_board_cb},
	{"router.system", "info", provisioning_ubus_info_cb},
	{"router.system", "fs", provisioning_ubus_fs_cb},
	{"router.system", "memory_bank", provisioning_ubus_memory_cb},
};

int provisioning_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_RUNNING, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	error = sr_oper_get_items_subscribe(session, PROVISIONING_YANG_MODEL, PROVISIONING_XPATH_BASE, provisioning_state_data_cb, *private_data, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("plugin init done");

	goto out;

error_out:
	sr_unsubscribe(subscription);

out:

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

void provisioning_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int provisioning_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	int error = SRPO_UBUS_ERR_OK;
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data = {
		.lookup_path = NULL, .method = NULL, .transform_data_cb = NULL, .timeout = 0, .json_call_arguments = NULL};

	if (strcmp(path, PROVISIONING_XPATH_BASE) != 0 && strcmp(path, "*") != 0)
		return SR_ERR_OK;

	for (size_t j = 0; j < ARRAY_SIZE(provisioning_provider_table); j++) {
		srpo_ubus_init_result_values(&values);

		ubus_call_data.lookup_path = provisioning_provider_table[j].module;
		ubus_call_data.method = provisioning_provider_table[j].method;
		ubus_call_data.transform_data_cb = provisioning_provider_table[j].transform_data;

		error = srpo_ubus_call(values, &ubus_call_data);
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto out;
		}

		error = store_ubus_values_to_datastore(session, request_xpath, values, parent);
		// TODO fix error handling here
		if (error) {
			SRP_LOG_ERR("store_ubus_values_to_datastore error (%d)", error);
			goto out;
		}

		srpo_ubus_free_result_values(values);
		values = NULL;
	}

out:
	if (values) {
		srpo_ubus_free_result_values(values);
	}

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static void provisioning_ubus_board_cb(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	char *string = NULL;
	json_object *result = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	for (size_t i = 0; i < ARRAY_SIZE(provisioning_ubus_board_map); i++) {
		if (!provisioning_ubus_board_map[i].transform_data)
			goto cleanup;

		string = (provisioning_ubus_board_map[i].transform_data)(result, provisioning_ubus_board_map[i].parent_name, provisioning_ubus_board_map[i].name);
		if (!string)
			goto cleanup;

		error = srpo_ubus_result_values_add(values,
											string, strlen(string),
											provisioning_ubus_board_map[i].xpath, strlen(provisioning_ubus_board_map[i].xpath),
											provisioning_ubus_board_map[i].name, strlen(provisioning_ubus_board_map[i].name));
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_result_values_add error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto cleanup;
		}

		FREE_SAFE(string);
	}

cleanup:
	FREE_SAFE(string);

	json_object_put(result);
	return;
}

static void provisioning_ubus_info_cb(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	char *string = NULL;
	json_object *result = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	for (size_t i = 0; i < ARRAY_SIZE(provisioning_ubus_info_map); i++) {
		if (!provisioning_ubus_info_map[i].transform_data)
			goto cleanup;

		string = (provisioning_ubus_info_map[i].transform_data)(result, provisioning_ubus_info_map[i].parent_name, provisioning_ubus_info_map[i].name);
		if (!string)
			goto cleanup;

		error = srpo_ubus_result_values_add(values,
											string, strlen(string),
											provisioning_ubus_info_map[i].xpath, strlen(provisioning_ubus_info_map[i].xpath),
											provisioning_ubus_info_map[i].name, strlen(provisioning_ubus_info_map[i].name));
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_result_values_add error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto cleanup;
		}

		FREE_SAFE(string);
	}

cleanup:
	FREE_SAFE(string);

	json_object_put(result);
	return;
}

static void provisioning_ubus_fs_cb(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	char *string = NULL;
	json_object *result = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	for (size_t i = 0; i < ARRAY_SIZE(provisioning_ubus_fs_map); i++) {
		if (!provisioning_ubus_fs_map[i].transform_data)
			goto cleanup;

		string = (provisioning_ubus_fs_map[i].transform_data)(result, provisioning_ubus_fs_map[i].parent_name, provisioning_ubus_fs_map[i].name);
		if (!string)
			goto cleanup;

		error = srpo_ubus_result_values_add(values,
											string, strlen(string),
											provisioning_ubus_fs_map[i].xpath, strlen(provisioning_ubus_fs_map[i].xpath),
											provisioning_ubus_fs_map[i].name, strlen(provisioning_ubus_fs_map[i].name));
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_result_values_add error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto cleanup;
		}

		FREE_SAFE(string);
	}

cleanup:
	FREE_SAFE(string);

	json_object_put(result);
	return;
}

static void provisioning_ubus_memory_cb(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	char *string = NULL;
	json_object *result = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);

	for (size_t i = 0; i < ARRAY_SIZE(provisioning_ubus_memory_map); i++) {
		if (!provisioning_ubus_memory_map[i].transform_data)
			goto cleanup;

		string = (provisioning_ubus_memory_map[i].transform_data)(result, provisioning_ubus_memory_map[i].parent_name, provisioning_ubus_memory_map[i].name);
		if (!string)
			goto cleanup;

		error = srpo_ubus_result_values_add(values,
											string, strlen(string),
											provisioning_ubus_memory_map[i].xpath, strlen(provisioning_ubus_memory_map[i].xpath),
											provisioning_ubus_memory_map[i].name, strlen(provisioning_ubus_memory_map[i].name));
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_result_values_add error (%d): %s", error, srpo_ubus_error_description_get(error));
			goto cleanup;
		}

		FREE_SAFE(string);
	}

cleanup:
	FREE_SAFE(string);

	json_object_put(result);
	return;
}

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent)
{
	const struct ly_ctx *ly_ctx = NULL;
	if (*parent == NULL) {
		ly_ctx = sr_get_context(sr_session_get_connection(session));
		if (ly_ctx == NULL) {
			return -1;
		}
		*parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
	}

	for (size_t i = 0; i < values->num_values; i++) {
		lyd_new_path(*parent, NULL, values->values[i].xpath, values->values[i].value, 0, 0);
	}

	return 0;
}

#ifndef PLUGIN
#include <signal.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
	int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = provisioning_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("provisioning_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	provisioning_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
