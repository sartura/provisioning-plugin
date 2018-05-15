#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#include "uci.h"

#define ARR_SIZE(a) sizeof a / sizeof a[0]

typedef struct ctx_s {
	const char *yang_model;
	sr_session_ctx_t *sess;
	sr_subscription_ctx_t *sub;
} ctx_t;

typedef struct ubus_ctx_s {
	ctx_t *ctx;
	sr_val_t **values;
	size_t *values_cnt;
} ubus_ctx_t;

typedef struct ubus_data_s {
    struct json_object *fs; // ubus call router.system fs
    struct json_object *info; // ubus call router.system info
    struct json_object *memory_bank; // ubus call router.system memory_bank
    struct json_object *board; // ubus call system board
    struct json_object *tmp;
} ubus_data_t;

struct value_node {
    struct list_head head;
    sr_val_t value;
};
