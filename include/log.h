#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

// 初始化：可以指定 log 檔路徑，若為 NULL 則輸出到 stderr
int log_init(const char *filepath, log_level_t level);

// 設定 runtime log level
void log_set_level(log_level_t level);

// 結束時關閉檔案
void log_close(void);

// 實際 log 函式
void log_write(log_level_t level, const char *fmt, ...);

// 方便的 macro
#define LOG_DEBUG(fmt, ...) log_write(LOG_LEVEL_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_write(LOG_LEVEL_INFO,  "[INFO ] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_write(LOG_LEVEL_WARN,  "[WARN ] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_write(LOG_LEVEL_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // LOG_H
