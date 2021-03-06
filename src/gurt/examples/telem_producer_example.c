/*
 * (C) Copyright 2020-2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/*
 * This file shows an example of using the telemetry API to produce metrics
 */

#include "gurt/telemetry_common.h"
#include "gurt/telemetry_producer.h"

/**
 * A sample function that creates and incremements a metric for a loop counter
 *
 * \param[in]	count	Number of loop iterations
 */
void test_function1(int count)
{
	static struct d_tm_node_t	*loop;
	int				rc;
	int				i;

	/**
	 * The first iteration initializes the pointer to the metric.
	 * On subsequent iterations, the pointer is used and the path name
	 * information is ignored.  If the same counter were to be used
	 * elsewhere, it can be referenced using only the initialized pointer
	 * if desired.  See the final d_tm_increment_counter() below.
	 */
	for (i = 0; i < count - 1; i++) {
		rc = d_tm_increment_counter(&loop, 1, "loop counter");
		if (rc != DER_SUCCESS) {
			printf("d_tm_increment_counter failed: " DF_RC "\n",
			       DP_RC(rc));
			return;
		}
	}

	/**
	 * Demonstrates how the metric is accessed by the initialized pointer.
	 * No name is required.  The API uses the initialized pointer if it is
	 * provided, and only uses the name if the pointer doesn't reference
	 * anything.
	 */
	rc = d_tm_increment_counter(&loop, 1, NULL);
	if (rc != DER_SUCCESS)
		printf("d_tm_increment_counter failed: " DF_RC "\n", DP_RC(rc));

}

/**
 * A sample function that creates and records a timestamp that indicates when
 * this function is called.
 */
void test_function2(void)
{
	static struct d_tm_node_t	*ts;
	int				rc;

	rc = d_tm_record_timestamp(&ts, "last executed");
	if (rc != DER_SUCCESS)
		printf("d_tm_record_timestamp failed: " DF_RC "\n", DP_RC(rc));
}

/**
 * A sample function that shows how a gauge is incremented, say when opening
 * a handle.  Note that num_open_handles, like all other d_tm_node_t variables
 * is declared as static.  This allows the pointer to be initialized the first
 * time the d_tm_increment_gauge() is called, and is simply used on subsequent
 * function calls.
 */
void test_open_handle(void)
{
	static struct d_tm_node_t	*num_open_handles;
	int				rc;

	/**
	 * Create / use a gauge at a known location so that it can be used by
	 * test_close_handle() without sharing pointers.  The gauge can be
	 * incremented by an arbitrary value.  We will incrememt by one for this
	 * example.
	 */
	rc = d_tm_increment_gauge(&num_open_handles, 1, "handles/open handles");
	if (rc != DER_SUCCESS)
		printf("d_tm_increment_gauge failed: " DF_RC "\n", DP_RC(rc));
}

/**
 * A sample function that shows how a gauge is decremented, say when closing
 * a handle.  It uses the same gauge as the one referenced in test_open_handle()
 * as it is initially referenced by the same name.  Had the pointer been shared,
 * it would have been used instead.
 */
void test_close_handle(void)
{
	static struct d_tm_node_t	*num_open_handles;
	int				rc;

	/**
	 * The full name of this gauge matches the name in test_open_handle() so
	 * that increments in test_open_handle() are changing the same metric
	 * as the one used here.
	 */
	rc = d_tm_decrement_gauge(&num_open_handles, 1, "handles/open handles");
	if (rc != DER_SUCCESS)
		printf("d_tm_decrement_gauge failed: " DF_RC "\n", DP_RC(rc));
}

/**
 * Shows use of the timer snapshot.  It allows the developer to take
 * high resolution timer snapshots at various places within their code, which
 * can then be interpreted depending on the need.  A duration type metric
 * is a simplified version of this metric that does the interval calculation.
 * When the timer shapshot is created, specify the clock type from:
 * D_TM_CLOCK_REALTIME which is CLOCK_REALTIME
 * D_TM_CLOCK_PROCESS_CPUTIME which is CLOCK_PROCESS_CPUTIME_ID
 * D_TM_CLOCK_THREAD_CPUTIME which is CLOCK_THREAD_CPUTIME_ID
 */
void timer_snapshot(void)
{
	static struct d_tm_node_t	*t1;
	static struct d_tm_node_t	*t2;
	static struct d_tm_node_t	*t3;
	static struct d_tm_node_t	*t4;
	static struct d_tm_node_t	*t5;
	static struct d_tm_node_t	*t6;
	struct timespec			ts;
	int				rc;
	int				snap = 0;

	rc = d_tm_take_timer_snapshot(&t1, D_TM_CLOCK_REALTIME,
				      "snapshot %d", ++snap);
	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));

	/** Do some stuff */
	sleep(1);

	rc = d_tm_take_timer_snapshot(&t2, D_TM_CLOCK_REALTIME,
				      "snapshot %d", ++snap);
	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));

	/** Do some stuff */
	ts.tv_sec = 0;
	ts.tv_nsec = 50000000;
	nanosleep(&ts, NULL);

	rc = d_tm_take_timer_snapshot(&t3, D_TM_CLOCK_REALTIME,
				      "snapshot %d", ++snap);
	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));

	/** Do some stuff (10x longer) */
	ts.tv_sec = 0;
	ts.tv_nsec = 500000000;
	nanosleep(&ts, NULL);

	rc = d_tm_take_timer_snapshot(&t4, D_TM_CLOCK_REALTIME,
				      "snapshot %d", ++snap);
	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));

	/**
	 * How long did the sleep(1) take?  That's t2 - t1
	 * How long did the 50000 iterations take?  That's t3 - t2
	 * How long did the 500000 iterations take?  That's t4 - t3.
	 * How long did the sleep(1) and the 50000 iterations take?  That's
	 * t3 - t1.
	 * When was function entry?  That's t1.
	 * When did the function exit the sleep(1)?  That's t t2.
	 */

	/** This is how to specify a high resolution process CPU timer */
	rc = d_tm_take_timer_snapshot(&t5, D_TM_CLOCK_PROCESS_CPUTIME,
				      "snapshot %d", ++snap);

	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));

	/** This is how to specify a high resolution thread CPU timer */
	rc = d_tm_take_timer_snapshot(&t6, D_TM_CLOCK_THREAD_CPUTIME,
				      "snapshot %d", ++snap);
	if (rc != DER_SUCCESS)
		printf("d_tm_take_timer_snapshot failed: " DF_RC "\n",
		       DP_RC(rc));
}

/**
 * Demonstrates how to use d_tm_add_metric to create a metric explicitly.
 * When doing so, it allows the developer to add metadata to the metric.
 * Initializing the metric early may be helpful for avoiding the overhead of
 * creating the metric the first time when it is needed.  Either create the
 * metric in the function that will use it, or keep track of the pointers with
 * a d_tm_nodeList_t for use elsewhere.
 *
 * \return	Pointer to a d_tm_nodeList if successful
 *		NULL if failure
 */
struct d_tm_nodeList_t *add_metrics_manually(void)
{
	struct d_tm_nodeList_t	*node_list = NULL;
	struct d_tm_node_t	*counter1 = NULL;
	struct d_tm_node_t	*counter2 = NULL;
	int			rc;

	/**
	 * Create some metrics manually, and keep track of the pointers by
	 * adding them to a d_tm_nodeList_t for later usage.
	 */
	rc = d_tm_add_metric(&counter1, D_TM_COUNTER,
			     "A manually added counter",
			     "If I had a lot to say about it, I'd write that "
			     "here.  I have D_TM_MAX_LONG_LEN characters "
			     "to use.",
			     "manually added/counter 1");
	if (rc != DER_SUCCESS) {
		printf("d_tm_add_metric failed: " DF_RC "\n", DP_RC(rc));
		return NULL;
	}

	rc = d_tm_add_node(counter1, &node_list);
	if (rc != DER_SUCCESS) {
		printf("d_tm_add_metric failed: " DF_RC "\n", DP_RC(rc));
		return NULL;
	}

	rc = d_tm_add_metric(&counter2, D_TM_COUNTER,
			     "Another manually added counter",
			     "Much less metadata to report this time.",
			     "manually added/counter 2");
	if (rc != DER_SUCCESS) {
		d_tm_list_free(node_list);
		printf("d_tm_add_metric failed: " DF_RC "\n", DP_RC(rc));
		return NULL;
	}

	rc = d_tm_add_node(counter2, &node_list);
	if (rc != DER_SUCCESS) {
		d_tm_list_free(node_list);
		printf("d_tm_add_metric failed: " DF_RC "\n", DP_RC(rc));
		return NULL;
	}

	return node_list;
}

/**
 * Iterate through a d_tm_nodeList_t and increment any counter found, just to
 * show one way of using pointers to metrics that were initialized explicitly
 * in some location other than exactly where it is being used.
 *
 * \param[in]	node_list	A list of metrics that were previously added
 */
void use_manually_added_metrics(struct d_tm_nodeList_t *node_list)
{
	int	rc;

	while (node_list) {
		switch (node_list->dtnl_node->dtn_type) {
		case D_TM_DIRECTORY:
			break;
		case D_TM_COUNTER:
			/**
			 * Supplying an initialized pointer to the metric
			 * so it is only used and not created implicitly here.
			 */
			rc = d_tm_increment_counter(&node_list->dtnl_node, 1,
						    NULL);
			if (rc != DER_SUCCESS) {
				printf("d_tm_increment_counter failed: "
				       DF_RC "\n", DP_RC(rc));
			}
			break;
		default:
			printf("Item: %s has unknown type: 0x%x\n",
			       node_list->dtnl_node->dtn_name,
			       node_list->dtnl_node->dtn_type);
			break;
		}
		node_list = node_list->dtnl_next;
	}
}

int
main(int argc, char **argv)
{
	static struct d_tm_node_t	*entry;
	static struct d_tm_node_t	*loop;
	static struct d_tm_node_t	*timer1;
	static struct d_tm_node_t	*timer2;
	struct d_tm_nodeList_t		*node_list;
	int				rc;
	int				simulated_srv_idx = 0;
	int				i;

	if (argc < 2) {
		printf("Specify an integer that identifies this producer's "
		       "sever instance.  "
		       "Specify the same value to the consumer.\n");
		exit(0);
	}

	simulated_srv_idx = atoi(argv[1]);
	printf("This simulated server instance has ID: %d\n",
	       simulated_srv_idx);

	/**
	 * Call d_tm_init() only once per process,
	 * i.e. in engine/init.c::server_init()
	 */
	rc = d_tm_init(simulated_srv_idx, D_TM_SHARED_MEMORY_SIZE,
		       D_TM_RETAIN_SHMEM);
	if (rc != 0)
		goto failure;

	/**
	 * The API is ready to use.  Add a counter that will be identified in
	 * the tree by this file name, function name, and the name "sample
	 * counter", i.e.:
	 * "src/gurt/examples/telem_producer_example.c/main/sample counter"
	 *
	 * On the first call through, the pointer to this metric is NULL, and
	 * the API looks up the metric by name.  It won't find it, so it creates
	 * it.  The counter is created, and incremented by one.  It now has the
	 * value 1.
	 */
	rc = d_tm_increment_counter(&entry, 1, "sample_counter");
	if (rc != DER_SUCCESS) {
		printf("d_tm_increment_counter failed: " DF_RC "\n", DP_RC(rc));
		goto failure;
	}

	/**
	 * Increment another counter in a loop.
	 * On the first iteration, the API finds the metric by name and
	 * initializes 'loop'.  On subsequent iterations, the pointer is used
	 * for faster lookup.
	 */
	for (i = 0; i < 1000; i++) {
		rc = d_tm_increment_counter(&loop, 1, "loop counter");
		if (rc != DER_SUCCESS) {
			printf("d_tm_increment_counter failed: " DF_RC "\n",
			       DP_RC(rc));
			goto failure;
		}
	}

	/**
	 * How long does it take to execute test_function()?
	 * When the duration timer is created, specify the clock type from:
	 * D_TM_CLOCK_REALTIME which is CLOCK_REALTIME
	 * D_TM_CLOCK_PROCESS_CPUTIME which is CLOCK_PROCESS_CPUTIME_ID
	 * D_TM_CLOCK_THREAD_CPUTIME which is CLOCK_THREAD_CPUTIME_ID
	 */

	/** For the first timer, let's use the realtime clock */
	rc = d_tm_mark_duration_start(&timer1, D_TM_CLOCK_REALTIME,
				      "10000 iterations with rt clock");
	if (rc != DER_SUCCESS) {
		printf("d_tm_mark_duration_start failed: " DF_RC "\n",
		       DP_RC(rc));
		goto failure;
	}

	test_function1(10000);
	rc = d_tm_mark_duration_end(&timer1, rc, NULL);
	if (rc != DER_SUCCESS) {
		printf("d_tm_mark_duration_end failed: " DF_RC "\n", DP_RC(rc));
		goto failure;
	}

	/** For the second timer, let's use the process clock */
	rc = d_tm_mark_duration_start(&timer2, D_TM_CLOCK_PROCESS_CPUTIME,
				      "10000 iterations with process clock");
	if (rc != DER_SUCCESS) {
		printf("d_tm_mark_duration_start failed: " DF_RC "\n",
		       DP_RC(rc));
		goto failure;
	}

	test_function1(10000);
	rc = d_tm_mark_duration_end(&timer2, rc, NULL);
	if (rc != DER_SUCCESS) {
		printf("d_tm_mark_duration_end failed: " DF_RC "\n", DP_RC(rc));
		goto failure;
	}

	/**
	 * Notice that the test_function1() metric named 'loop counter'
	 * should have the value 20000 because test_function1(10000) was called
	 * twice and the counter persists in shared memory beyond the life of
	 * the function call itself.
	 */

	/**
	 * test_function2() records a timestamp that shows when the function was
	 * last executed.
	 */
	test_function2();

	/**
	 * Open a handle 1000 times.  The sample function increments a gauge
	 * that monitors how many open handles.
	 */
	for (i = 0; i < 1000; i++)
		test_open_handle();

	/**
	 * Close the same handle 750 times.  The sample function decrements the
	 * same gauge as above.
	 */
	for (i = 0; i < 750; i++)
		test_close_handle();

	/**
	 * The client application will show that the gauge shows 250 open
	 * handles.
	 */

	/** Trying out the high resolution timer snapshot*/
	timer_snapshot();

	/**
	 * Add some metrics manually using the long form.  This lets us add
	 * some metadata at initialization time.  It also allows us to
	 * initialize the metric before it is needed, which can improve
	 * performance if the area being instrumented is particularly sensitive
	 * to that initial creation time.  Subsequent uses of the metric may
	 * be accessed by a pointer and avoid the cost of the lookup, just like
	 * when the metrics are created implicitly with the other functions.
	 */
	node_list = add_metrics_manually();
	if (node_list == NULL)
		goto failure;

	/**
	 * After calling add_metrics_manually, the counters have value = 0
	 * Each call to use_manually_added_metrics() increments the counters
	 * by 1.  After the three calls, they should have value = 3.
	 * This simply demonstrates how to use the node pointers that were
	 * initialized when adding the metrics manually.
	 */
	for (i = 0; i < 3; i++)
		use_manually_added_metrics(node_list);
	d_tm_list_free(node_list);

	d_tm_fini();

	printf("Metrics added and ready to read.  Try the example consumer.\n");
	return 0;

failure:
	d_tm_fini();
	return -1;
}
