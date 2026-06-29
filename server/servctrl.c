//
// Created by gf-senka on 6/7/2026.
//

#include "servctrl.h"
#include "netwrap.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include "clhandle.h"
#include "cmdparse.h"
#include "ipblock.h"
#include "zlog.h"
#define CMD_STRSIZE 256
#define ZLOG_LEVEL_CTRL 121

#define dzlog_ctrl(format, ...) dzlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
    ZLOG_LEVEL_CTRL, format, ##__VA_ARGS__)

#define X_CMDS(X) \
    X(help, "help\n") \
    X(shutdown_server, "shutdown_server\n") \
    X(registrations, "registrations <bool>\n") \
    X(show, "show <object(users, loadfactor, std_ipblock_list, reg_ipblock_list, whitelist)>\n") \
    X(std_ipblock, "std_ipblock <users...(max 19)>\n") \
    X(std_unblock, "std_unblock <users...(max 19)>\n") \
    X(reg_ipblock, "reg_ipblock <users...(max 19)>\n") \
    X(reg_unblock, "reg_unblock <users...(max 19)>\n") \
    X(whitelist, "whitelist <users...(max 19)>\n") \
    X(unwhitelist, "unwhitelist <users...(max 19)>\n") \
    X(filesize, "filesize <UINT64>\n") \
    X(filetransfers, "filetransfers <bool>\n") \
    X(whitelist_use, "whitelist_use <bool>\n") \
    X(set_log, "set_log <level(DEBUG/INFO/NOTICE/WARN/ERROR/FATAL)>\n")


enum cmds
{
#define X_CMD_ENUMVALS(cmd, man) cmd,
    X_CMDS(X_CMD_ENUMVALS)
#undef X_CMD_ENUMVALS
};

static const char* ctrl_if_path = "/tmp/lwmsg.ctrl";

static const char commands[][2][CMD_STRSIZE] = {
#define X_CMD_STRINGS(cmd, man) [cmd] = {#cmd, man},
    X_CMDS(X_CMD_STRINGS)
#undef X_CMD_STRINGS
};

static const uint32_t num_commands = sizeof(commands) / sizeof(commands[0]);

FILE* open_ctrl_if()
{
    FILE* cifp = fopen(ctrl_if_path, "r+");
    struct stat st;
    if (cifp && !fstat(fileno(cifp), &st) && S_ISFIFO(st.st_mode))
        return cifp;
    else if (cifp)
    {
        dzlog_ctrl("Control FIFO path already taken by a non-FIFO inode. Aborting lwmsgctrl");
        fclose(cifp);
        return NULL;
    }

    if (mkfifo(ctrl_if_path, 0600) == ERROR)
    {
        char errbuf[256] = {0};
        strerror_r(errno, errbuf, 256);
        dzlog_ctrl("Failed to create lwmsgctrl FIFO. Reason: %s. Aborting lwmsgctrl", errbuf);
        return NULL;
    }

    cifp = fopen(ctrl_if_path, "r+");
    if (!cifp)
        dzlog_ctrl("Failed to open lwmsgctrl FIFO. Aborting lwmsgctrl");

    return cifp;
}

void close_ctrl_if(FILE* cifp)
{
    if (!cifp)
        return;

    fclose(cifp);
    remove(ctrl_if_path);
}

int32_t ctrl_parse_input(FILE* cifp, char line[1024], char** tokens)
{
    char* res = fgets(line, 1024, cifp);
    if (!res)
    {
        char errbuf[256] = {0};
        strerror_r(errno, errbuf, 256);
        dzlog_ctrl("Error parsing input. Cause: %s", errbuf);
        return ERROR;
    }

    char* newline = strrchr(line, '\n');
    if (newline)
        *newline = '\0';

    normalize_string(line);
    int32_t tok_count = cmdparse_tokenize(line, tokens, MAX_TOKENS_PER_LINE);
    return tok_count;
}

static void handle_ctrl_help(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    uint32_t k = 0;
    char helpbuf[num_commands * CMD_STRSIZE];
    for (uint32_t i = 0; i < num_commands; i++)
    {
        for (uint32_t j = 0; commands[i][1][j] != '\0'; j++)
        {
            helpbuf[k++] = commands[i][1][j];
        }
    }
    helpbuf[k] = '\0';
    dzlog_ctrl("List of commands and usage:\n%s", helpbuf);
}

static void handle_ctrl_shutdown_server(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    eventfd_write(ctrlctx->flg_shutdown, 1);
    dzlog_ctrl("Shutdown command sent");
}

static int64_t handle_generic_flag_change(const uint8_t* flag, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return ERROR;
    }
    char* endptr = NULL;
    int64_t arg = strtol(tokens[1], &endptr, 10);
    if (tokens[1] == endptr || (arg != 0 && arg != 1))
    {
        dzlog_ctrl("Invalid argument for %s. Expected a bool (0 or 1).", tokens[0]);
        return ERROR;
    }

    if (arg == __atomic_load_n(flag, __ATOMIC_SEQ_CST))
    {
        dzlog_ctrl("[%s] Argument is equal to the current state of the flag, having no effect.", tokens[0]);
        return ERROR;
    }

    return arg;
}

static void handle_ctrl_registrations(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    int64_t arg = handle_generic_flag_change(&g_server_cfg->allow_registrations, tokens, token_cnt);
    if (arg == ERROR)
        return;

    __atomic_store_n(&g_server_cfg->allow_registrations, arg, __ATOMIC_SEQ_CST);
    eventfd_write(ctrlctx->flg_reg_changed, 1);
    dzlog_ctrl("%s registrations.", arg ? "Enabled" : "Disabled");
}

static void handle_ctrl_show(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return;
    }

    if (!strcmp(tokens[1], "users"))
    {
        char* users = NULL;
        uint64_t userssize = htable_copy_all_keys(ctrlctx->std_cl_tbl, (void**)&users, node_copy_username);
        uint64_t i = 0;
        if (userssize)
        {
            for (uint64_t off = 0; off < userssize; off++)
            {
                if (users[off] == '\0')
                {
                    users[off] = '\n';
                    i++;
                }
            }
            users[userssize - 1] = '\0';
            dzlog_ctrl("Connected and authenticated users (%lu):\n%s", i, users);
            free(users);
        }
        else
            dzlog_ctrl("There are no connected users.");
    }
    else if (!strcmp(tokens[1], "loadfactor"))
    {
        dzlog_ctrl("Client table load factor: %.4lf", htable_get_ldfactor(ctrlctx->std_cl_tbl));
    }
    else if (!strcmp(tokens[1], "std_ipblock_list") || !strcmp(tokens[1], "reg_ipblock_list") || !strcmp(tokens[1], "whitelist"))
    {
        striped_htable* iptbl = !strcmp(tokens[1], "std_ipblock_list") ? ctrlctx->std_ipblock_tbl
                              : !strcmp(tokens[1], "reg_ipblock_list") ? ctrlctx->reg_ipblock_tbl
                              : ctrlctx->ip_whitelist_tbl;
        char* peernames = NULL;
        uint64_t peernamessize = htable_copy_all_keys(iptbl, (void**)&peernames, node_copy_peername);
        uint64_t i = 0;
        if (peernamessize)
        {
            for (uint64_t off = 0; off < peernamessize; off++)
            {
                if (peernames[off] == '\0')
                {
                    peernames[off] = '\n';
                    i++;
                }
            }
            peernames[peernamessize - 1] = '\0';
            dzlog_ctrl("%s records (%lu):\n%s", tokens[1], i, peernames);
            free(peernames);
        }
        else
            dzlog_ctrl("There are no records in %s", tokens[1]);
    }
    else
    {
        dzlog_ctrl("Unsupported argument for show: %s", tokens[1]);
    }
}

static void handle_ctrl_std_ipblock(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return;
    }

    for (uint32_t i = 1; i < token_cnt; i++)
    {
        in_addr_t peername = inet_addr(tokens[i]);
        if (peername == INADDR_NONE)
        {
            dzlog_ctrl("[%s] Invalid peer name: %s", tokens[0], tokens[i]);
            continue;
        }

        std_ipb_rec* stdipbr = std_ipb_rec_create(peername, true);
        bool add_res = htable_add(ctrlctx->std_ipblock_tbl, &stdipbr->nd);
        if (!add_res)
        {
            dzlog_ctrl("Record %s already present in %s table.", tokens[i], tokens[0]);
            node_put(&stdipbr->nd);
        }
        else
            dzlog_ctrl("Added record %s to %s table.", tokens[i], tokens[0]);
    }
}

static void generic_remove(striped_htable* table, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return;
    }

    for (uint32_t i = 1; i < token_cnt; i++)
    {
        in_addr_t peername = inet_addr(tokens[i]);
        if (peername == INADDR_NONE)
        {
            dzlog_ctrl("[%s] Invalid peer name: %s", tokens[0], tokens[i]);
            continue;
        }

        htable_remove(table, &peername, sizeof(peername));
        dzlog_ctrl("Removed record %s from %s if it was present.", tokens[i], tokens[0]);
    }
}

static void handle_ctrl_std_unblock(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    generic_remove(ctrlctx->std_ipblock_tbl, tokens, token_cnt);
}

static void handle_ctrl_reg_ipblock(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return;
    }

    for (uint32_t i = 1; i < token_cnt; i++)
    {
        in_addr_t peername = inet_addr(tokens[i]);
        if (peername == INADDR_NONE)
        {
            dzlog_ctrl("[%s] Invalid peer name: %s", tokens[0], tokens[i]);
            continue;
        }

        reg_ipb_rec* ripbr = reg_ipb_rec_create(peername, RSN_MANUAL);
        bool add_res = htable_add(ctrlctx->reg_ipblock_tbl, &ripbr->nd);
        if (!add_res)
        {
            dzlog_ctrl("Record %s already present in %s table.", tokens[i], tokens[0]);
            node_put(&ripbr->nd);
        }
        else
            dzlog_ctrl("Added record %s to %s table.", tokens[i], tokens[0]);
    }
}

static void handle_ctrl_reg_unblock(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    generic_remove(ctrlctx->reg_ipblock_tbl, tokens, token_cnt);
}

static void handle_ctrl_whitelist(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s.", tokens[0]);
        return;
    }

    for (uint32_t i = 1; i < token_cnt; i++)
    {
        in_addr_t peername = inet_addr(tokens[i]);
        if (peername == INADDR_NONE)
        {
            dzlog_ctrl("[%s] Invalid peer name: %s", tokens[0], tokens[i]);
            continue;
        }

        whitelist_rec* wrec = whitelist_rec_create(peername);
        bool add_res = htable_add(ctrlctx->ip_whitelist_tbl, &wrec->nd);
        if (!add_res)
        {
            dzlog_ctrl("Record %s already present in %s table.", tokens[i], tokens[0]);
            node_put(&wrec->nd);
        }
        else
            dzlog_ctrl("Added record %s to %s table.", tokens[i], tokens[0]);
    }
}

static void handle_ctrl_unwhitelist(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    generic_remove(ctrlctx->ip_whitelist_tbl, tokens, token_cnt);
}

static void handle_ctrl_filesize(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s", tokens[0]);
        return;
    }

    char* endptr = NULL;
    errno = 0;
    uint64_t arg = strtoull(tokens[1], &endptr, 10);
    if (tokens[1] == endptr || *endptr != '\0' || errno == ERANGE)
    {
        dzlog_ctrl("Invalid argument for %s. Expected a UINT64", tokens[0]);
        return;
    }

    __atomic_store_n(&g_server_cfg->max_filesize_b, arg, __ATOMIC_SEQ_CST);
    dzlog_ctrl("Changed max filesize to %lu", arg);
}

static void handle_ctrl_filetransfers(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    int64_t res = handle_generic_flag_change(&g_server_cfg->allow_file_transfers, tokens, token_cnt);
    if (res == ERROR)
        return;

    __atomic_store_n(&g_server_cfg->allow_file_transfers, res, __ATOMIC_SEQ_CST);
    dzlog_ctrl("%s file transfers.", res ? "Enabled" : "Disabled");
}

static void handle_ctrl_whitelist_use(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    int64_t res = handle_generic_flag_change(&g_server_cfg->use_ip_whitelist, tokens, token_cnt);
    if (res == ERROR)
        return;

    __atomic_store_n(&g_server_cfg->use_ip_whitelist, res, __ATOMIC_SEQ_CST);
    dzlog_ctrl("%s whitelist.", res ? "Using" : "Not using");
}

static void handle_ctrl_set_log(ctrl_ctx* ctrlctx, char** tokens, int32_t token_cnt)
{
    if (token_cnt < 2)
    {
        dzlog_ctrl("Invalid number of arguments for %s", tokens[0]);
        return;
    }
    zlog_level log_level = ERROR;

    if (!strcmp(tokens[1], "debug"))
    {
        log_level = ZLOG_LEVEL_DEBUG;
    }
    else if (!strcmp(tokens[1], "info"))
    {
        log_level = ZLOG_LEVEL_INFO;
    }
    else if (!strcmp(tokens[1], "notice"))
    {
        log_level = ZLOG_LEVEL_NOTICE;
    }
    else if (!strcmp(tokens[1], "warn"))
    {
        log_level = ZLOG_LEVEL_WARN;
    }
    else if (!strcmp(tokens[1], "error"))
    {
        log_level = ZLOG_LEVEL_ERROR;
    }
    else if (!strcmp(tokens[1], "fatal"))
    {
        log_level = ZLOG_LEVEL_FATAL;
    }

    if (log_level == ERROR)
    {
        dzlog_ctrl("Invalid log level");
        return;
    }

    dzlog_ctrl("Setting log level to %s", tokens[1]);
    zlog_level_switch(ctrlctx->zct, log_level);
}

bool ctrl_process_cmd(ctrl_ctx* ctrlctx, char** tokens, int32_t num_tokens)
{
    if (!num_tokens || !tokens)
    {
        dzlog_ctrl("Invalid ctrl input.");
        return true;
    }

    uint32_t icmd = 0;
    for (;icmd < num_commands; icmd++)
    {
        if (!strcmp(tokens[0], commands[icmd][0]))
            break;
    }


#define X_CMD_HANDLE(cmd, man) case cmd: {handle_ctrl_##cmd(ctrlctx, tokens, num_tokens); break;}
    switch (icmd)
    {
        X_CMDS(X_CMD_HANDLE)
        default:
            dzlog_ctrl("Invalid command: %s", tokens[0]);
    }
#undef X_CMD_HANDLE

    if (icmd == shutdown_server)
        return false;
    else
        return true;
}