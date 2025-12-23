#include "ipc.h"

#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <unistd.h>

/*
 * SysV semctl union definition.
 * Some libcs do not define union semun, so it is explicitly declared here
 * for use with semctl() SETVAL / IPC_RMID operations.
 */
union semun {
    int val;                // Value for SETVAL
    struct semid_ds *buf;   // Buffer for IPC_STAT, IPC_SET
    unsigned short *array;  // Array for GETALL, SETALL
};

/*
 * Initialize a System V semaphore set as a binary semaphore.
 * Only semaphore 0 is used; it is set to 1, meaning "unlocked/available".
 *
 * Return:
 *   0  on success
 *  -1  on failure
 */
static int ipc_init_semaphore(int sem_id) {
    union semun arg;
    arg.val = 1; // Binary semaphore initial value = 1 (resource available)
    if (semctl(sem_id, 0, SETVAL, arg) == -1) {
        return -1;
    }
    return 0;
}

/*
 * Create shared memory and semaphore for server-side statistics.
 *
 * This function:
 *   1. Creates a shared memory segment sized for ipc_server_stats_t.
 *   2. Creates a semaphore set containing a single semaphore.
 *   3. Attaches the shared memory into the process address space.
 *   4. Initializes the stats structure to zero.
 *   5. Initializes the semaphore as a binary lock.
 *
 * On any failure, it cleans up all allocated IPC resources.
 *
 * Parameters:
 *   handle  - Output handle that stores shm_id, sem_id, and stats pointer.
 *   shm_key - Key used for shmget() to identify the shared memory segment.
 *   sem_key - Key used for semget() to identify the semaphore set.
 *
 * Return:
 *   0  on success
 *  -1  on failure
 */
int ipc_create(ipc_handle_t *handle, key_t shm_key, key_t sem_key) {
    if (!handle) return -1;
    memset(handle, 0, sizeof(*handle));

    // Create a new shared memory segment exclusively
    int shm_id = shmget(shm_key, sizeof(ipc_server_stats_t),
                        IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id == -1) {
        return -1;
    }

    // Create a new semaphore set with 1 semaphore
    int sem_id = semget(sem_key, 1, IPC_CREAT | IPC_EXCL | 0666);
    if (sem_id == -1) {
        // If semaphore creation fails, remove the shared memory segment
        shmctl(shm_id, IPC_RMID, NULL);
        return -1;
    }

    // Attach the shared memory to the current process
    void *addr = shmat(shm_id, NULL, 0);
    if (addr == (void *)-1) {
        // Clean up both shared memory and semaphore if attachment fails
        shmctl(shm_id, IPC_RMID, NULL);
        semctl(sem_id, 0, IPC_RMID);
        return -1;
    }

    // Store identifiers and mapped address in the handle
    handle->shm_id = shm_id;
    handle->sem_id = sem_id;
    handle->stats  = (ipc_server_stats_t *)addr;

    // Initialize the statistics structure in shared memory
    memset(handle->stats, 0, sizeof(ipc_server_stats_t));

    // Initialize the semaphore as a binary lock
    if (ipc_init_semaphore(sem_id) < 0) {
        shmdt(handle->stats);
        shmctl(shm_id, IPC_RMID, NULL);
        semctl(sem_id, 0, IPC_RMID);
        return -1;
    }

    return 0;
}

/*
 * Detach the shared memory from the current process.
 *
 * Note:
 *   This does not remove the shared memory segment from the system;
 *   it only unmaps it from this process. The actual removal is done
 *   via ipc_destroy() on the creator/owner side.
 */
int ipc_detach(ipc_handle_t *handle) {
    if (!handle || !handle->stats) return -1;
    if (shmdt(handle->stats) == -1) return -1;
    handle->stats = NULL;
    return 0;
}

/*
 * Destroy IPC resources (shared memory and semaphore).
 *
 * Intended to be called by the process that is responsible for the
 * lifetime of these resources (typically the server). It:
 *   - Detaches the shared memory from this process if still attached.
 *   - Marks the shared memory segment to be removed (IPC_RMID).
 *   - Marks the semaphore set to be removed (IPC_RMID).
 *
 * Other processes that still have the shared memory attached can
 * continue using it until they detach, but no new attachments will
 * succeed after removal is requested.
 */
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

/*
 * Acquire the semaphore (lock).
 *
 * This implements a classic "P" operation on a binary semaphore:
 *   - Decrements semaphore 0 by 1.
 *   - If the value becomes negative, the caller blocks until it
 *     can acquire the lock.
 *
 * SEM_UNDO is used so the kernel can automatically adjust the semaphore
 * if the process exits unexpectedly, reducing the chance of deadlocks.
 */
int ipc_lock(ipc_handle_t *handle) {
    if (!handle) return -1;

    struct sembuf op;
    op.sem_num = 0;   // Use the first (and only) semaphore in the set
    op.sem_op  = -1;  // P operation: try to decrement (lock)
    op.sem_flg = SEM_UNDO;

    if (semop(handle->sem_id, &op, 1) == -1) {
        return -1;
    }
    return 0;
}

/*
 * Release the semaphore (unlock).
 *
 * This implements a classic "V" operation:
 *   - Increments semaphore 0 by 1.
 *   - If other processes are blocked in ipc_lock(), one of them
 *     will be woken up and allowed to proceed.
 */
int ipc_unlock(ipc_handle_t *handle) {
    if (!handle) return -1;

    struct sembuf op;
    op.sem_num = 0;   // Use the first (and only) semaphore in the set
    op.sem_op  = 1;   // V operation: increment (unlock)
    op.sem_flg = SEM_UNDO;

    if (semop(handle->sem_id, &op, 1) == -1) {
        return -1;
    }
    return 0;
}
