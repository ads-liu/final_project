#include "ipc.h"

#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <unistd.h>

// SysV semctl union 定義
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

static int ipc_init_semaphore(int sem_id) {
    union semun arg;
    arg.val = 1; // binary semaphore
    if (semctl(sem_id, 0, SETVAL, arg) == -1) {
        return -1;
    }
    return 0;
}

int ipc_create(ipc_handle_t *handle, key_t shm_key, key_t sem_key) {
    if (!handle) return -1;
    memset(handle, 0, sizeof(*handle));

    int shm_id = shmget(shm_key, sizeof(ipc_server_stats_t), IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id == -1) {
        // 若已存在可以改用 attach，但這裡先簡單當錯誤
        return -1;
    }

    int sem_id = semget(sem_key, 1, IPC_CREAT | IPC_EXCL | 0666);
    if (sem_id == -1) {
        shmctl(shm_id, IPC_RMID, NULL);
        return -1;
    }

    void *addr = shmat(shm_id, NULL, 0);
    if (addr == (void *)-1) {
        shmctl(shm_id, IPC_RMID, NULL);
        semctl(sem_id, 0, IPC_RMID);
        return -1;
    }

    handle->shm_id = shm_id;
    handle->sem_id = sem_id;
    handle->stats  = (ipc_server_stats_t *)addr;

    memset(handle->stats, 0, sizeof(ipc_server_stats_t));

    if (ipc_init_semaphore(sem_id) < 0) {
        shmdt(handle->stats);
        shmctl(shm_id, IPC_RMID, NULL);
        semctl(sem_id, 0, IPC_RMID);
        return -1;
    }

    return 0;
}

int ipc_attach(ipc_handle_t *handle, key_t shm_key, key_t sem_key) {
    if (!handle) return -1;
    memset(handle, 0, sizeof(*handle));

    int shm_id = shmget(shm_key, sizeof(ipc_server_stats_t), 0666);
    if (shm_id == -1) return -1;

    int sem_id = semget(sem_key, 1, 0666);
    if (sem_id == -1) return -1;

    void *addr = shmat(shm_id, NULL, 0);
    if (addr == (void *)-1) return -1;

    handle->shm_id = shm_id;
    handle->sem_id = sem_id;
    handle->stats  = (ipc_server_stats_t *)addr;

    return 0;
}

int ipc_detach(ipc_handle_t *handle) {
    if (!handle || !handle->stats) return -1;
    if (shmdt(handle->stats) == -1) return -1;
    handle->stats = NULL;
    return 0;
}

int ipc_destroy(ipc_handle_t *handle) {
    if (!handle) return -1;
    if (handle->stats) {
        shmdt(handle->stats);
        handle->stats = NULL;
    }
    if (handle->shm_id > 0) {
        shmctl(handle->shm_id, IPC_RMID, NULL);
    }
    if (handle->sem_id > 0) {
        semctl(handle->sem_id, 0, IPC_RMID);
    }
    return 0;
}

int ipc_lock(ipc_handle_t *handle) {
    if (!handle) return -1;

    struct sembuf op;
    op.sem_num = 0;
    op.sem_op  = -1; // P
    op.sem_flg = SEM_UNDO;

    if (semop(handle->sem_id, &op, 1) == -1) {
        return -1;
    }
    return 0;
}

int ipc_unlock(ipc_handle_t *handle) {
    if (!handle) return -1;

    struct sembuf op;
    op.sem_num = 0;
    op.sem_op  = 1; // V
    op.sem_flg = SEM_UNDO;

    if (semop(handle->sem_id, &op, 1) == -1) {
        return -1;
    }
    return 0;
}
