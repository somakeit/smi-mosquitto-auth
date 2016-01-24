#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <string.h>
#include <bcrypt.h>
#include <curl/curl.h>

#define LINE_BUFFER 128

int use_smi_auth = 0;
int use_password_file_auth = 0;
char *smi_auth_url;
char *password_file;

int load_option(char auth_option_key[], char auth_option_value[]) {
    if (strcmp(auth_option_key, "smi_auth_url") == 0) {
        if (auth_option_value[0] == '\0') {
            mosquitto_log_printf(MOSQ_LOG_ERR, "SMI Auth Option %s invalid.", auth_option_key);
            return(1);
        }
        use_smi_auth = 1;
        smi_auth_url = (char*)malloc((strlen(auth_option_value) + 1) * sizeof(char));
        mosquitto_log_printf(MOSQ_LOG_INFO, "len: %d str: %s", (strlen(auth_option_value) + 1), auth_option_value);
        strcpy(smi_auth_url, auth_option_value);
        return(0);
    }
    else if (strcmp(auth_option_key, "password_file") == 0) {
        FILE *f;
        if (f = fopen(auth_option_value, "r")) {
            fclose(f);
            use_password_file_auth = 1;
            password_file = (char*)malloc((strlen(auth_option_value) + 1) * sizeof(char));
            strcpy(password_file, auth_option_value);
            return(0);
        }
        else {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Password file %s is not readable or does not exist.", auth_option_value);
            return(1);
        }
    }
    else {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Unknown SMI Auth Option: %s", auth_option_key);
        return(1);
    }
}

int mosquitto_auth_plugin_version(void) {
    return(MOSQ_AUTH_PLUGIN_VERSION);
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
    mosquitto_log_printf(MOSQ_LOG_INFO, "SMI Auth Plugin Loaded.");
    for (int i = 0; i < auth_opt_count ; i++) {
        int rc;
        rc = load_option(auth_opts->key, auth_opts->value);
        if (rc == 0) {
            mosquitto_log_printf(MOSQ_LOG_INFO, "SMI auth option %s: %s", auth_opts->key, auth_opts->value);
        }
        else {
            return(rc);
        }
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

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
    /* Check the password file first */
    if (use_password_file_auth) {
        FILE *f;
        f = fopen(password_file, "r");
        if (f == NULL) {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Password file gone!");
            return(MOSQ_ERR_UNKNOWN);
        }

        while (1) {
            char buffer[LINE_BUFFER];
            char file_user_name[LINE_BUFFER];
            char file_password[LINE_BUFFER];
            char *tok;

            if (fgets(buffer, LINE_BUFFER, f) == NULL) break;
            //chomp
            strtok(buffer, "\n");

            tok = strtok(buffer, ":");
            if (tok == NULL) {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Malformed line in password file");
                return(MOSQ_ERR_UNKNOWN);
            }
            else {
                strcpy(file_user_name, tok);
            }
            tok = strtok(NULL, ":");
            if (tok == NULL) {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Malformed line in password file");
                return(MOSQ_ERR_UNKNOWN);
            }
            else {
                strcpy(file_password, tok);
            }

            if (strcmp(file_user_name, username) == 0) {
                if (bcrypt_checkpw(password, file_password) == 0) {
                    return(MOSQ_ERR_SUCCESS);
                }
                else {
                    return(MOSQ_ERR_AUTH);
                }
            }
        }
    }

    if (use_smi_auth) {
        //construct POST payload
        char *payload;
        payload = (char*)malloc((strlen("email=&password=") + strlen(username) + strlen(password) + 1) * sizeof(char));
        sprintf(payload, "email=%s&password=%s", username, password);

        //construct the request
        CURL *curl;
        CURLcode result;
        long status_code;
        int request_failed = 0;
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();
        mosquitto_log_printf(MOSQ_LOG_INFO, "POST %s to %s", payload, smi_auth_url);

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, smi_auth_url);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

            //make the request
            result = curl_easy_perform(curl);
            if (result != CURLE_OK) {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Request to auth server failed: %s", curl_easy_strerror(result));
                request_failed = 1;
            }
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
            curl_easy_cleanup(curl);
        }
        else {
             mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to get a curl handle");
             request_failed = 1;
        }
        curl_global_cleanup();
        free(payload);

        if (request_failed) {
            return(MOSQ_ERR_UNKNOWN);
        }

        switch (status_code) {
            case 200:
                return(MOSQ_ERR_SUCCESS);
            case 404:
                return(MOSQ_ERR_AUTH);
            default:
                mosquitto_log_printf(MOSQ_LOG_ERR, "Auth server returned unexpected status: %d", status_code);
                return(MOSQ_ERR_UNKNOWN);
        }
    }

    return(MOSQ_ERR_AUTH);
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
    return(1);
}
