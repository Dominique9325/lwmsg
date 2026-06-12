//
// Created by gf-senka on 6/7/2026.
//

#include "servctrl.h"
#include "netwrap.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define VARARG (-1)
#define LOCAL 0
#define ROUTED 1

#define X_COMMAND_CODES(X) \
    X(STOP_SERVER) \
    X(DISCONNECT) \
    X(FILETRANSFER_ALLOW) \
    X(WHITELIST_USE) \
    X(WHITELIST_ADD) \
    X(WHITELIST_REMOVE) \
    X(BLOCKLIST_ADD) \
    X(BLOCKLIST_REMOVE) \
    X(KICK_USER) \
    X(BAN_USER) \
    X(UNBAN_USER) \
    X(HELP) \
    X(REGISTRATIONS_ALLOW) \
    X(LIST_COMMANDS) \
    X(GLOBHELP) \
    X(WHITELIST_DISPLAY) \
    X(BLOCKLIST_DISPLAY) \


enum command_code
{
#define X_ENUM_FIELDS(enumval) enumval,
    X_COMMAND_CODES(X_ENUM_FIELDS)
#undef X_ENUM_FIELDS
};

command commands[] = {
                      {STOP_SERVER, "stop_server", 0, ROUTED},
                      {DISCONNECT, "disconnect", 0, LOCAL},
                      {FILETRANSFER_ALLOW, "filetransfer_allow", 1, ROUTED},
                      {WHITELIST_USE, "whitelist_use", 1, ROUTED},
                      {WHITELIST_ADD, "whitelist_add", VARARG, ROUTED},
                      {WHITELIST_REMOVE, "whitelist_remove", VARARG, ROUTED},
                      {WHITELIST_DISPLAY, "whitelist_display", 0, ROUTED},
                      {BLOCKLIST_ADD, "blocklist_add", VARARG, ROUTED},
                      {BLOCKLIST_REMOVE, "blocklist_remove", VARARG, ROUTED},
                      {BLOCKLIST_DISPLAY, "blocklist_display", 0, ROUTED},
                      {KICK_USER, "kick_user", VARARG, ROUTED},
                      {BAN_USER, "ban_user", VARARG, ROUTED},
                      {UNBAN_USER, "unban_user", VARARG, ROUTED},
                      {HELP, "help", 1, LOCAL},
                      {REGISTRATIONS_ALLOW, "registrations_allow", 1, ROUTED},
                      {LIST_COMMANDS, "list_commands", 0, LOCAL},
                      {GLOBHELP, "glob", 0, LOCAL}
                     };

char cmd_manuals[][256] = {
    [STOP_SERVER] = "Initiates server shutdown, disconnecting all the clients.",
    [DISCONNECT] = "Disconnects the control client from the server's control interface.",
    [FILETRANSFER_ALLOW] = "Toggles whether users may send files or not. Usage: filetransfer_allow <bool>",
    [WHITELIST_USE] = "Toggles whitelist usage. If the whitelist is active, only whitelisted peers may connect. Whitelisted peers are still subject to rules of the IP blocklist. Usage: whitelist_use <bool>",
    [WHITELIST_ADD] = "Adds provided IPv4 peer names to the whitelist. Usage: whitelist_add <peer name> ...",
    [WHITELIST_REMOVE] = "Removes provided IPv4 peer names to the whitelist. Usage: whitelist_remove <peer name> ...",
    [BLOCKLIST_ADD] = "Adds provided IPv4 peer names to the IP blocklist with an indefinite expiration. Usage: blocklist_add <peer name> ...",
    [BLOCKLIST_REMOVE] = "Removes provided IPv4 peer names from the IP blocklist. Usage: blocklist_remove <peer name> ...",
    [KICK_USER] = "Kicks users with the provided usernames from the server. Usage: kick <username> ...",
    [BAN_USER] = "Bans users with the provided usernames from the server. Usage: ban <username> ...",
    [UNBAN_USER] = "Unbans users with the provided usernames from the server. Usage: unban <username> ...",
    [HELP] = "Displays a command's manual, which includes the effect of the command and the usage. For global help use \"help glob\". Usage: help <command name>",
    [REGISTRATIONS_ALLOW] = "Toggles whether connections to the registration interface (and as such, new registration attempts) will be allowed. Usage: registrations_allow <bool>",
    [LIST_COMMANDS] = "Lists all supported commands. For more detailed information about a command, use \"help <command name>\".",
    [GLOBHELP] = "'?' next to an argument indicates that it is optional, '...' indicates it's variadic (1 or more arguments of the same type)."
};

uint8_t command_count = sizeof(commands) / sizeof(commands[0]);

int32_t ctrl_read_cmd(int32_t sockfd, void* buf, int32_t bufsize)
{
    int32_t bytes_read = 0;
    int32_t total_read = 0;

    while (total_read < bufsize && (bytes_read = (int32_t)read(sockfd, buf + total_read, bufsize - total_read)) > 0)
        total_read += bytes_read > 0 ? bytes_read : 0;

    int32_t error;
    if (!bytes_read || (bytes_read == ERROR && (error = errno) != EAGAIN))
        return ERROR;


}