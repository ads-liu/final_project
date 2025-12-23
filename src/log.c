#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Simple global logging backend.
 *
 * g_log_fp    - Current log output stream (file or stderr).
 * g_log_level - Minimum severity level that will be written.
 *
 * Note:
 *   This logger is process-wide and not re-entrant in configuration,
 *   but log_write() uses stdio stream locking to be safe with multiple threads.
 */
static FILE *g_log_fp = NULL;
static log_level_t g_log_level = LOG_LEVEL_DEBUG;

/*
 * Initialize the logging system.
 *
 * Parameters:
 *   filepath - Path to the log file. If NULL, logs go to stderr.
 *   level    - Initial log level threshold.
 *
 * Behavior:
 *   - If filepath is NULL or fopen fails, logging falls back to stderr.
 *   - On success, subsequent log_write() calls will append to the given file.
 *
 * Return:
 *   0  on success (or when falling back to stderr).
 *  -1  if opening the specified file failed (still logs to stderr).
 */
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

/*
 * Change the global log level at runtime.
 *
 * Messages with severity below this level will be ignored.
 */
void log_set_level(log_level_t level) {
    g_log_level = level;
}

/*
 * Close the current log file if it is not stderr.
 *
 * After this call, logging will be disabled until log_init() is called again
 * (log_write() will reinitialize g_log_fp to stderr lazily if needed).
 */
void log_close(void) {
    if (g_log_fp && g_log_fp != stderr) {
        fclose(g_log_fp);
    }
    g_log_fp = NULL;
}

/*
 * Convert a log_level_t to a short string prefix.
 *
 * Used in log_write() to print a human-readable severity label.
 */
static const char *level_to_str(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        default:              return "UNK";
    }
}

/*
 * Write a formatted log message with timestamp and level.
 *
 * Parameters:
 *   level - Severity of this message.
 *   fmt   - printf-style format string followed by variable arguments.
 *
 * Output format (one line per call):
 *   [YYYY-MM-DD HH:MM:SS] [LEVEL] message...\n
 *
 * Thread-safety:
 *   - Uses flockfile()/funlockfile() to ensure that each entire log line
 *     is written atomically on g_log_fp, avoiding interleaved output when
 *     multiple threads log at the same time. [web:61][web:65][web:67][web:70]
 *
 * Behavior:
 *   - If g_log_fp is NULL, it is lazily initialized to stderr.
 *   - Messages with level < g_log_level are discarded silently.
 */
void log_write(log_level_t level, const char *fmt, ...) {
    if (!g_log_fp) g_log_fp = stderr;
    if (level < g_log_level) return;

    // Generate local time stamp
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);  // Thread-safe variant of localtime [web:72]

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);

    // Lock the FILE* so that this whole log line is written as a unit
    flockfile(g_log_fp);        // Block until this thread owns the stream [web:65][web:70]

    // Print timestamp and level header
    fprintf(g_log_fp, "[%s] [%s] ", timebuf, level_to_str(level));

    // Print user-provided message body
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log_fp, fmt, ap);
    va_end(ap);

    // Terminate the line and flush to ensure it hits disk/terminal promptly
    fprintf(g_log_fp, "\n");
    fflush(g_log_fp);

    // Release the FILE* lock so other threads can write
    funlockfile(g_log_fp);      // Decrement lock count and release ownership [web:65][web:76][web:80]
}
