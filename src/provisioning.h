#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#define ARR_SIZE(a) sizeof a / sizeof a[0]

struct plugin_ctx {
    sr_subscription_ctx_t *subscription;
    sr_conn_ctx_t *startup_connection;
    sr_session_ctx_t *startup_session;
};
