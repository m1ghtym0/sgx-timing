#include "set_sched.h"
#include <stdio.h>

// pin to process to cpu
int pin_cpu(int cpu) {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity( 0, sizeof( cpu_set_t ), &set )) {
			perror( "sched_setaffinity" );
			return -1;
	}
	return 0;
}

int set_real_time_sched_priority(int policy, int priority){
	struct sched_param param;
	if (priority) {
		// set min sched priority
		param.sched_priority = sched_get_priority_max(policy);;
	} else {
		// set max sched priority
		param.sched_priority = sched_get_priority_min(policy);;
	}
	if (sched_setscheduler(0, policy, &param) != 0) {
			perror("sched_setscheduler");
			return -1;
	}
	return 0;
}

