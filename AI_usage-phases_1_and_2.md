I used Claude (claude.ai) to suggest me with the following.


```c static sig_atomic_t should_exit => static volatile sig_atomic_t should_exit```
It advised me to change its type due to potential problems: without volatile, the compiler is allowed to cache the variable's value in a register and never re-read it from memory. This means the while (should_exit == 0) loop could run forever even after the signal handler sets it to 1, because the compiler optimized away the memory read. volatile forces the compiler to always read the variable from memory on every check.
Solution advised: add volatile to the declaration.

```c fflush(stdout)```
printf("monitor: raport nou adaugat.\n"); => wasn't displaying in the terminal immediately after the signal was received.
It advised me that printf writes to an internal stdio buffer, not directly to the screen. That buffer is only flushed automatically when it fills up or when the program exits cleanly. Since a signal handler can fire at any point and the process may be killed shortly after, the message could stay stuck in the buffer and never appear.
Solution advised: call fflush(stdout) immediately after every printf inside signal handlers.

**Bonus: how sigaction handlers are built**
Claude also explained why sigaction() must be used instead of signal(). The signal() function has unspecified behaviour on many platforms — on some systems it resets the handler to the default after each signal, meaning the second SIGUSR1 would terminate the process. sigaction() is the POSIX standard: it keeps the handler installed, allows masking other signals during handler execution via sa_mask, and gives explicit control over flags like SA_RESTART. The sa_flags = 0 setting is intentional — it ensures pause() is interrupted by the signal rather than automatically restarted, which is what allows the main loop to check should_exit and exit cleanly.