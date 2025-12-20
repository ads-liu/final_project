#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FILE *g_log_fp = NULL;
static log_level_t g_log_level = LOG_LEVEL_DEBUG;

int log_init(const char *filepath, log_level_t level) {
    g_log_level = level;
    if (filepath == NULL) {
        g_log_fp = stderr;
        return 0;
    }

    g_log_fp = fopen(filepath, "a");
    if (!g_log_fp) {
        g_log_fp = stderr;
        return -1;
    }
    return 0;
}

void log_set_level(log_level_t level) {
    g_log_level = level;
}

void log_close(void) {
    if (g_log_fp && g_log_fp != stderr) {
        fclose(g_log_fp);
    }
    g_log_fp = NULL;
}

static const char *level_to_str(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        default:              return "UNK";
    }
}

void log_write(log_level_t level, const char *fmt, ...) {
    if (!g_log_fp) g_log_fp = stderr;
    if (level < g_log_level) return;

    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);

    flockfile(g_log_fp);

    fprintf(g_log_fp, "[%s] [%s] ", timebuf, level_to_str(level));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log_fp, fmt, ap);
    va_end(ap);

    fprintf(g_log_fp, "\n");
    fflush(g_log_fp);

    funlockfile(g_log_fp);
}
