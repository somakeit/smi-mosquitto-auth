#include <stdbool.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_plugin_version(void) {
    return(MOSQ_AUTH_PLUGIN_VERSION);
}

/*
 * Function: mosquitto_auth_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_auth_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Parameters:
 *
 *	user_data :      The pointer set here will be passed to the other plugin
 *	                 functions. Use to hold connection information for example.
 *	auth_opts :      Pointer to an array of struct mosquitto_auth_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	auth_opt_count : The number of elements in the auth_opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
    mosquitto_log_printf(MOSQ_LOG_INFO, "SMI Auth Plugin Loaded.");
    for (int i = 0; i < auth_opt_count ; i++) {
        mosquitto_log_printf(MOSQ_LOG_INFO, "SMI auth option %s: %s", auth_opts->key, auth_opts->value);
        auth_opts++;
    }

    return(0);
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
    return(0);
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
    return(0);
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
    return(0);
}

/*
 * Function: mosquitto_auth_acl_check
 *
 * Called by the broker when topic access must be checked. access will be one
 * of MOSQ_ACL_READ (for subscriptions) or MOSQ_ACL_WRITE (for publish). Return
 * MOSQ_ERR_SUCCESS if access was granted, MOSQ_ERR_ACL_DENIED if access was
 * not granted, or MOSQ_ERR_UNKNOWN for an application specific error.
 */
int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {
    return(MOSQ_ERR_SUCCESS);
}

/*
 * Function: mosquitto_auth_unpwd_check
 *
 * Called by the broker when a username/password must be checked. Return
 * MOSQ_ERR_SUCCESS if the user is authenticated, MOSQ_ERR_AUTH if
 * authentication failed, or MOSQ_ERR_UNKNOWN for an application specific
 * error.
 */
int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
    return(MOSQ_ERR_SUCCESS);
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
    return(1);
}
