/*
 * Author: Paul Reioux aka Faux123 <reioux@gmail.com>
 *
 * Copyright 2012~2014 Paul Reioux
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

// #define DEBUG

#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cpufreq.h>

#define DEF_SAMPLING_MS			(268)

#define DUAL_PERSISTENCE		(2500 / DEF_SAMPLING_MS)
#define TRI_PERSISTENCE			(1700 / DEF_SAMPLING_MS)
#define QUAD_PERSISTENCE		(1000 / DEF_SAMPLING_MS)

#define BUSY_PERSISTENCE		(3500 / DEF_SAMPLING_MS)

static DEFINE_MUTEX(intelli_plug_mutex);

static struct delayed_work intelli_plug_work;

static struct workqueue_struct *intelliplug_wq;

static __read_mostly bool enabled = false;
static __read_mostly unsigned int nr_run_profile_sel = 0;

//default to something sane rather than zero
static __read_mostly unsigned int sampling_time = DEF_SAMPLING_MS;

static int param_set_enabled(const char *val,
			const struct kernel_param *kp)
{
	int ret = param_set_bool(val, kp);

	queue_delayed_work_on(0, intelliplug_wq, &intelli_plug_work,
		msecs_to_jiffies(sampling_time));

	return ret;
}

static const struct kernel_param_ops enabled_param_ops = {
	.set = param_set_enabled,
	.get = param_get_bool,
};

module_param_cb(enabled, &enabled_param_ops, &enabled, 0664);
module_param(nr_run_profile_sel, uint, 0664);

static int persist_count = 0;

static __read_mostly bool suspended = false;

struct ip_cpu_info {
	unsigned int sys_max;
	unsigned int cur_max;
	unsigned long cpu_nr_running;
};

static DEFINE_PER_CPU(struct ip_cpu_info, ip_info);

static __read_mostly unsigned int screen_off_max = 600000;
module_param(screen_off_max, uint, 0664);

#define CAPACITY_RESERVE	50

#if defined(CONFIG_ARCH_APQ8084) || defined(CONFIG_ARM64)
#define THREAD_CAPACITY (430 - CAPACITY_RESERVE)
#elif defined(CONFIG_ARCH_MSM8960) || defined(CONFIG_ARCH_APQ8064) || \
defined(CONFIG_ARCH_MSM8974)
#define THREAD_CAPACITY	(339 - CAPACITY_RESERVE)
#elif defined(CONFIG_ARCH_MSM8226) || defined (CONFIG_ARCH_MSM8926) || \
defined (CONFIG_ARCH_MSM8610) || defined (CONFIG_ARCH_MSM8228)
#define THREAD_CAPACITY (190 - CAPACITY_RESERVE)
#else
#define THREAD_CAPACITY	(250 - CAPACITY_RESERVE)
#endif

#define MULT_FACTOR	4
#define DIV_FACTOR	100000
#define NR_FSHIFT	3

static __read_mostly unsigned int nr_fshift = NR_FSHIFT;

static const unsigned int nr_run_thresholds_balance[] = {
	(THREAD_CAPACITY * 625 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 875 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 1125 * MULT_FACTOR) / DIV_FACTOR,
	UINT_MAX
};

static const unsigned int nr_run_thresholds_performance[] = {
	(THREAD_CAPACITY * 380 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 625 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 875 * MULT_FACTOR) / DIV_FACTOR,
	UINT_MAX
};

static const unsigned int nr_run_thresholds_conservative[] = {
	(THREAD_CAPACITY * 875 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 1625 * MULT_FACTOR) / DIV_FACTOR,
	(THREAD_CAPACITY * 2125 * MULT_FACTOR) / DIV_FACTOR,
	UINT_MAX
};

static const unsigned int nr_run_thresholds_eco[] = {
        (THREAD_CAPACITY * 380 * MULT_FACTOR) / DIV_FACTOR,
	UINT_MAX
};

static const unsigned int nr_run_thresholds_eco_extreme[] = {
        (THREAD_CAPACITY * 750 * MULT_FACTOR) / DIV_FACTOR,
	UINT_MAX
};

static const unsigned int nr_run_thresholds_disable[] = {
	0,  0,  0,  UINT_MAX
};

static const unsigned int *nr_run_profiles[] = {
	nr_run_thresholds_balance,
	nr_run_thresholds_performance,
	nr_run_thresholds_conservative,
	nr_run_thresholds_eco,
	nr_run_thresholds_eco_extreme,
	nr_run_thresholds_disable,
};

#define NR_RUN_ECO_MODE_PROFILE	3

#define CPU_NR_THRESHOLD	((THREAD_CAPACITY << 1) + (THREAD_CAPACITY / 2))

static __read_mostly unsigned int cpu_nr_run_threshold = CPU_NR_THRESHOLD;
module_param(cpu_nr_run_threshold, uint, 0664);

static unsigned int nr_run_last;

extern unsigned long avg_nr_running(void);
extern unsigned long avg_cpu_nr_running(unsigned int cpu);

static inline unsigned int calculate_thread_stats(void)
{
	unsigned int avg_nr_run = avg_nr_running();
	unsigned int nr_run;
	unsigned int threshold_size;
	const unsigned int *current_profile;

	current_profile = nr_run_profiles[nr_run_profile_sel];
	if (num_possible_cpus() > 2) {
		if (nr_run_profile_sel >= NR_RUN_ECO_MODE_PROFILE)
			threshold_size =
				ARRAY_SIZE(nr_run_thresholds_eco);
		else
			threshold_size =
				ARRAY_SIZE(nr_run_thresholds_balance);
	} else
		threshold_size =
			ARRAY_SIZE(nr_run_thresholds_eco);

	if (nr_run_profile_sel >= NR_RUN_ECO_MODE_PROFILE)
		nr_fshift = 1;
	else
		nr_fshift = num_possible_cpus() - 1;

	for (nr_run = 1; nr_run < threshold_size; nr_run++) {
		unsigned int nr_threshold;
		nr_threshold = current_profile[nr_run - 1];

		if (nr_run_last <= nr_run)
			nr_threshold += 8;
		if (avg_nr_run <= (nr_threshold << (FSHIFT - nr_fshift)))
			break;
	}
	nr_run_last = nr_run;

	return nr_run;
}

/*
static int cmp_nr_running(const void *a, const void *b)
{
	return *(unsigned long *)a - *(unsigned long *)b;
}
*/

static inline void update_per_cpu_stat(void)
{
	unsigned int cpu;
	struct ip_cpu_info *l_ip_info;

	for_each_online_cpu(cpu) {
		l_ip_info = &per_cpu(ip_info, cpu);
		l_ip_info->cpu_nr_running = avg_cpu_nr_running(cpu);
		pr_debug("cpu %u nr_running => %lu\n", cpu,
			l_ip_info->cpu_nr_running);
	}
}

static inline void unplug_cpu(int min_active_cpu)
{
	unsigned int cpu;
	struct ip_cpu_info *l_ip_info;
	int l_nr_threshold;

	for_each_online_cpu(cpu) {
		l_nr_threshold =
			cpu_nr_run_threshold << 1 / (num_online_cpus());
		if (cpu == 0)
			continue;
		l_ip_info = &per_cpu(ip_info, cpu);
		if (cpu > min_active_cpu)
			if (l_ip_info->cpu_nr_running < l_nr_threshold)
				cpu_down(cpu);
	}
}

static void __ref intelli_plug_work_fn(struct work_struct *work)
{
	unsigned int nr_run_stat;
	unsigned int cpu_count = 0;
	unsigned int nr_cpus = 0;

	int i;

	pr_debug("enabled: %d, suspended: %d\n",
	    enabled ? 1 : 0, suspended ? 1 : 0);

	if (enabled && !suspended) {
		nr_run_stat = calculate_thread_stats();
		update_per_cpu_stat();
		pr_debug("nr_run_stat: %u\n", nr_run_stat);
		cpu_count = nr_run_stat;
		nr_cpus = num_online_cpus();

		if (persist_count > 0)
			persist_count--;

		switch (cpu_count) {
		case 1:
			if (persist_count == 0) {
				//take down everyone
				unplug_cpu(0);
			}
			pr_debug("case 1: %u\n", persist_count);
			break;
		case 2:
			if (persist_count == 0)
				persist_count = DUAL_PERSISTENCE;
			if (nr_cpus < 2) {
				if (cpu_count >= 1)
					cpu_up(1);
			} else {
				unplug_cpu(1);
			}
			pr_debug("case 2: %u\n", persist_count);
			break;
		case 3:
			if (persist_count == 0)
				persist_count = TRI_PERSISTENCE;
			if (nr_cpus < 3) {
				if (cpu_count >= 1)
					cpu_up(1);
			} else {
				unplug_cpu(2);
			}
			pr_debug("case 3: %u\n", persist_count);
			break;
		case 4:
			if (persist_count == 0)
				persist_count = QUAD_PERSISTENCE;
			if (nr_cpus < 4)
				if (cpu_count >= 1)
					cpu_up(1);
			pr_debug("case 4: %u\n", persist_count);
			break;
		default:
			pr_err("Run Stat Error: Bad value %u\n", nr_run_stat);
			break;
		}
		queue_delayed_work_on(0, intelliplug_wq, &intelli_plug_work,
			msecs_to_jiffies(sampling_time));
	} else {
		pr_debug("intelli_plug is not active!\n");
	}
}

static void screen_off_limit(bool on)
{
	unsigned int cpu;
	struct cpufreq_policy *policy;
	struct ip_cpu_info *l_ip_info;

	/* not active, so exit */
	if (screen_off_max == UINT_MAX)
		return;

	for_each_online_cpu(cpu) {
		l_ip_info = &per_cpu(ip_info, cpu);
		policy = cpufreq_cpu_get(0);

		if (on) {
			/* save current instance */
			l_ip_info->cur_max = policy->max;
			policy->max = screen_off_max;
			policy->cpuinfo.max_freq = screen_off_max;
			pr_debug("cpuinfo max is (on): %u %u\n",
				policy->cpuinfo.max_freq, l_ip_info->sys_max);
		} else {
			/* restore */
			if (cpu != 0) {
				l_ip_info = &per_cpu(ip_info, 0);
			}
			policy->cpuinfo.max_freq = l_ip_info->sys_max;
			policy->max = l_ip_info->cur_max;
			pr_debug("cpuinfo max is (off): %u %u\n",
				policy->cpuinfo.max_freq, l_ip_info->sys_max);
		}
		cpufreq_update_policy(cpu);
	}
}

void intelli_plug_suspend(void)
{
	if (enabled) {
		int cpu;
	
		flush_workqueue(intelliplug_wq);

		mutex_lock(&intelli_plug_mutex);
		suspended = true;
		screen_off_limit(true);
		mutex_unlock(&intelli_plug_mutex);

		// put rest of the cores to sleep unconditionally!
		for_each_online_cpu(cpu) {
			if (cpu != 0)
				cpu_down(cpu);
		}
	}
}

void __ref intelli_plug_resume(void)
{
	if (enabled) {
		int cpu;

		mutex_lock(&intelli_plug_mutex);
		/* keep cores awake long enough for faster wake up */
		persist_count = BUSY_PERSISTENCE;
		suspended = false;
		mutex_unlock(&intelli_plug_mutex);

		// Boost 2nd core
		cpu_up(1);

		screen_off_limit(false);

		queue_delayed_work_on(0, intelliplug_wq, &intelli_plug_work,
			msecs_to_jiffies(10));
	}
}

int __init intelli_plug_init(void)
{
	int rc;
	struct cpufreq_policy *policy;
	struct ip_cpu_info *l_ip_info;

	l_ip_info = &per_cpu(ip_info, 0);
	policy = cpufreq_cpu_get(0);
	l_ip_info->sys_max = policy->cpuinfo.max_freq;
	l_ip_info->cur_max = policy->max;

	intelliplug_wq = alloc_workqueue("intelliplug",
				WQ_HIGHPRI | WQ_UNBOUND, 1);
	INIT_DELAYED_WORK(&intelli_plug_work, intelli_plug_work_fn);
	queue_delayed_work_on(0, intelliplug_wq, &intelli_plug_work,
		msecs_to_jiffies(10));

	return 0;
}

MODULE_AUTHOR("Paul Reioux <reioux@gmail.com>");
MODULE_DESCRIPTION("'intell_plug' - An intelligent cpu hotplug driver for "
	"Low Latency Frequency Transition capable processors");
MODULE_LICENSE("GPL");

late_initcall(intelli_plug_init);
