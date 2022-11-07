/* Dummy shared lib */
long batch_start();
long batch_flush();
long batch_flush_and_wait_some(int);
void init_worker(int);
void toggle_region();
