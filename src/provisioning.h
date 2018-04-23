#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

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
