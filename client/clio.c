#include "clio.h"
#include "clcmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <readline/readline.h>
#include <readline/history.h>

#define HISTORY_MAX 200

#define PROMPT_MAX 320
#define DEFAULT_PROMPT "> "

static client_ctx* g_clio_ctx;
static int g_in_handler;
static char g_prompt[PROMPT_MAX] = DEFAULT_PROMPT;

static const char* const commands[] = {
    "connect", "register", "disconnect", "msg", "sendfile",
    "userlist", "clear", "help", "quit", "q", NULL
};

static void clio_line_handler(char* line)
{
    if (!line)
    {
        g_clio_ctx->running = false;
        return;
    }
    if (*line)
        add_history(line);
    g_in_handler = 1;
    handle_command_line(g_clio_ctx, line);
    g_in_handler = 0;
    free(line);
}

static int32_t word_index(int32_t start)
{
    int32_t idx = 0;
    int32_t i = 0;
    while (i < start)
    {
        while (i < start && isspace((unsigned char)rl_line_buffer[i])) i++;
        if (i >= start) break;
        idx++;
        while (i < start && !isspace((unsigned char)rl_line_buffer[i])) i++;
    }
    return idx;
}

static char* command_generator(const char* text, int state)
{
    static int32_t idx;
    static size_t len;
    if (state == 0)
    {
        idx = 0;
        len = strlen(text);
    }
    const char* name;
    while ((name = commands[idx]) != NULL)
    {
        idx++;
        if (strncmp(name, text, len) == 0)
            return strdup(name);
    }
    return NULL;
}

static char* username_generator(const char* text, int state)
{
    static int32_t idx;
    static size_t len;
    if (state == 0)
    {
        idx = 0;
        len = strlen(text);
    }
    while (idx < g_clio_ctx->user_cache_count)
    {
        const char* uname = g_clio_ctx->user_cache[idx];
        idx++;
        if (strncmp(uname, text, len) == 0)
            return strdup(uname);
    }
    return NULL;
}

static char* defaulthost_generator(const char* text, int state)
{
    static int32_t done;
    if (state == 0)
        done = 0;
    if (!done && strncmp("defaulthost", text, strlen(text)) == 0)
    {
        done = 1;
        return strdup("defaulthost");
    }
    return NULL;
}

static char** lwmsg_completion(const char* text, int start, int end)
{
    (void)end;
    rl_attempted_completion_over = 1;

    int32_t widx = word_index(start);
    if (widx == 0)
        return rl_completion_matches(text, command_generator);

    char first[32] = {0};
    sscanf(rl_line_buffer, "%31s", first);

    if (strcmp(first, "help") == 0 && widx == 1)
        return rl_completion_matches(text, command_generator);

    if ((strcmp(first, "connect") == 0 || strcmp(first, "register") == 0) && widx == 1)
        return rl_completion_matches(text, defaulthost_generator);

    if ((strcmp(first, "msg") == 0 || strcmp(first, "sendfile") == 0) && widx == 1)
        return rl_completion_matches(text, username_generator);

    if (strcmp(first, "sendfile") == 0 && widx == 2)
    {
        rl_attempted_completion_over = 0;
        return NULL;
    }

    return NULL;
}

void clio_init(client_ctx* ctx)
{
    g_clio_ctx = ctx;
    snprintf(g_prompt, PROMPT_MAX, "lwmsg%s> ", ctx->use_tls ? "(TLS)" : "");
    using_history();
    stifle_history(HISTORY_MAX);
    rl_attempted_completion_function = lwmsg_completion;
    rl_callback_handler_install(g_prompt, clio_line_handler);
}

void clio_set_prompt(const char* prompt)
{
    strncpy(g_prompt, prompt, PROMPT_MAX - 1);
    g_prompt[PROMPT_MAX - 1] = '\0';
    rl_set_prompt(g_prompt);
    if (!g_in_handler)
        rl_redisplay();
}

void clio_reset_prompt(void)
{
    char prompt[PROMPT_MAX];
    snprintf(prompt, PROMPT_MAX, "lwmsg%s> ", g_clio_ctx->use_tls ? "(TLS)" : "");
    clio_set_prompt(prompt);
}

void clio_shutdown(void)
{
    rl_callback_handler_remove();
    clear_history();
}

void clio_on_stdin(void)
{
    rl_callback_read_char();
}

void clio_print(const char* fmt, ...)
{
    if (!g_in_handler)
        rl_clear_visible_line();

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);

    if (!g_in_handler)
    {
        rl_on_new_line();
        rl_redisplay();
    }
}
