#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

START_TEST(test_argv_buffer_overflow_invariant)
{
    /* Invariant: Processing adversarial argv strings must not cause
       memory corruption (crash/signal) — the program must exit cleanly
       or with a controlled error, never via SIGSEGV/SIGABRT. */
    const char *payloads[] = {
        /* Exact exploit: 512-byte overflow exceeding typical buffer */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* Boundary: exactly 255 chars (one under typical 256-byte buffer) */
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        /* Valid: short benign filename */
        "input.txt",
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        pid_t pid = fork();
        ck_assert_msg(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Child: invoke colossus with -c <payload> and redirect output */
            execl("./colossus", "colossus", "-c", payloads[i], NULL);
            _exit(127); /* exec failed */
        } else {
            int status = 0;
            waitpid(pid, &status, 0);

            if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                /* SIGSEGV=11, SIGABRT=6, SIGBUS=7 indicate memory corruption */
                ck_assert_msg(sig != SIGSEGV && sig != SIGABRT && sig != SIGBUS,
                    "colossus crashed with signal %d on payload[%d] — "
                    "buffer overflow detected", sig, i);
            }
            /* Controlled exit (any code) or normal termination is acceptable */
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 10);
    tcase_add_test(tc_core, test_argv_buffer_overflow_invariant);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}