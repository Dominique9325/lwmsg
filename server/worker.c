//
// Created by dominik on 6/18/26.
//

#include "thrdctx.h"
#include "worker.h"

void* worker_thrd_routine(void* worker_thread_ctx)
{
    if (!thrd_startup_sync())
        pthread_exit(NULL);

    worker_thrd_ctx* wt_ctx = (worker_thrd_ctx*)worker_thread_ctx;

}