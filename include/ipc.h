#ifndef IPC_H
#define IPC_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_JOBS   16
#define IMG_W      512
#define IMG_H      512
#define IMG_PIXELS (IMG_W * IMG_H)

typedef enum {
    JOB_EMPTY = 0,
    JOB_READY,
    JOB_DONE
} job_state_t;

typedef struct {
    job_state_t state;
    uint32_t    width;
    uint32_t    height;
    size_t      pixels;              // 方便 unsharp 用
    uint8_t     input[IMG_PIXELS];
    uint8_t     output[IMG_PIXELS];
} job_t;

typedef struct {
    uint64_t total_requests;
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;
    uint32_t active_connections;
    uint32_t shutdown_flag;
    job_t    jobs[MAX_JOBS];
} ipc_server_stats_t;

typedef struct {
    int shm_id;
    int sem_id;
    ipc_server_stats_t *stats;
} ipc_handle_t;

int ipc_create (ipc_handle_t *handle, key_t shm_key, key_t sem_key);
int ipc_attach (ipc_handle_t *handle, key_t shm_key, key_t sem_key);
int ipc_detach (ipc_handle_t *handle);
int ipc_destroy(ipc_handle_t *handle);
int ipc_lock   (ipc_handle_t *handle);
int ipc_unlock (ipc_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif // IPC_H
