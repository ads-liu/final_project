#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

// Initialization: optionally specify log file path, if NULL logs go to stderr
int log_init(const char *filepath, log_level_t level);

// Set runtime log level
void log_set_level(log_level_t level);

// Close log file at shutdown
void log_close(void);

// Core logging function
void log_write(log_level_t level, const char *fmt, ...);

// Convenience macros
#define LOG_DEBUG(fmt, ...) log_write(LOG_LEVEL_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_write(LOG_LEVEL_INFO,  "[INFO ] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_write(LOG_LEVEL_WARN,  "[WARN ] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_write(LOG_LEVEL_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)

#endif // LOG_H
