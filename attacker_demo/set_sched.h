#ifndef   SET_SCHED_H
#define   SET_SCHED_H

#define _GNU_SOURCE
#include <sched.h>

/*
 * Pins proces to specific CPU
 *
 * PARAMS: int cpu: ID of CPU process should be pinned to.
 * RETURN VALUE: Returns 0 in case of success, -1 otherwise.
 *
 */
int pin_cpu(int cpu);


/*
 * Sets realtime scheduling policy for process.
 *
 * PARAMS: int policy: Realtime policy:
 *                     - SCHED_FIFO: None preemtive
 *                     - SCHED_RR: Preemtive
 *         int priority: Lower integer means higher priority:
 *                     - 1: Lowest Realtime priority
 *                     - 0: Highest Realtime priority
 * RETURN VALUE: Returns 0 in case of success, -1 otherwise.
 *
 */
int set_real_time_sched_priority(int policy, int priority);

#endif
