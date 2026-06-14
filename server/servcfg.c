#include "servcfg.h"

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json_object.h>
#include <json-c/json.h>
#include "xalloc.h"

#define STR(X) #X
#define IS_INTEGRAL(X) (json_object_is_type(X, json_type_int) || json_object_is_type(X, json_type_boolean))

serv_cfg* g_server_cfg;

static serv_cfg get_default_cfg()
{
#define X_DEFAULTS(mtype, mname, mmin, mmax, mdef) .mname = mdef,
    serv_cfg cfg = {.padding = {0}, CFG_FIELDS(X_DEFAULTS)};
#undef X_DEFAULTS
    return cfg;
}

void load_cfg(const char* cfg_file)
{
    g_server_cfg = (serv_cfg*)xmalloc(sizeof(serv_cfg));
    serv_cfg temp_cfg;
    json_object* cfg_json;

    if (!cfg_file || !cfg_file[0] || !(cfg_json = json_object_from_file(cfg_file)))
    {
        printf("Loading default config.\n");
        temp_cfg = get_default_cfg();
        memcpy(g_server_cfg, &temp_cfg, sizeof(serv_cfg));
        return;
    }

    json_object* value_obj;
    uint64_t value;
    bool exists;

#define X_LD_INT(mtype, mname, mmin, mmax, mdef) \
    exists = json_object_object_get_ex(cfg_json, #mname, &value_obj); \
    if (!exists || !IS_INTEGRAL(value_obj) || \
        (value = (uint64_t)json_object_get_int64(value_obj)) < (uint64_t)(mmin) || \
        value > (uint64_t)(mmax)) \
    { \
        printf("Failed to load field %s, loading default instead.\n", #mname); \
        temp_cfg.mname = mdef; \
    } \
    else \
    { \
        temp_cfg.mname = value; \
    }

#define X_LD_STR(mtype, mname, mmin, mmax, mdef) \
    exists = json_object_object_get_ex(cfg_json, #mname, &value_obj); \
    if (!exists || !json_object_is_type(value_obj, json_type_string) || \
        json_object_get_string_len(value_obj) > (mmax) - 1) \
    { \
        printf("Failed to load field %s, loading default instead.\n", #mname); \
        strncpy(temp_cfg.mname, mdef, mmax); \
    } \
    else \
    { \
        strncpy(temp_cfg.mname, json_object_get_string(value_obj), mmax); \
    }

    CFG_INT_FIELDS(X_LD_INT)
    CFG_STR_FIELDS(X_LD_STR)

#undef X_LD_INT
#undef X_LD_STR

    json_object_put(cfg_json);
    memcpy(g_server_cfg, &temp_cfg, sizeof(serv_cfg));
}



void save_cfg(const char* cfg_file)
{
    json_object* cfg_json = json_object_new_object();
    json_object* value;

#define X_ST_INT(mtype, mname, mmin, mmax, mdef) \
    value = json_object_new_int64((int64_t)g_server_cfg->mname); \
    if (json_object_object_add(cfg_json, #mname, value) < 0) \
        printf("Failure to serialize field: %s\n", #mname);

#define X_ST_STR(mtype, mname, mmin, mmax, mdef) \
    value = json_object_new_string(g_server_cfg->mname); \
    if (json_object_object_add(cfg_json, #mname, value) < 0) \
        printf("Failure to serialize field: %s\n", #mname);

    CFG_INT_FIELDS(X_ST_INT)
    CFG_STR_FIELDS(X_ST_STR)
#undef X_ST_INT
#undef X_ST_STR

    if (json_object_to_file_ext(cfg_file, cfg_json, JSON_C_TO_STRING_PRETTY))
    {
        printf("Failed to save config. %s\n", strerror(errno));
    }
    json_object_put(cfg_json);
}
