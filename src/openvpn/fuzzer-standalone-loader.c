#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
    int n;

    for (n = 1; n < argc; ++n) {
        struct stat st;
        FILE *f;
        unsigned char *buf;
        size_t s;

        stat(argv[n], &st);
        f = fopen(argv[n], "rb");
        if (f == NULL)
            continue;
        buf = malloc(st.st_size);
        s = fread(buf, 1, st.st_size, f);
        LLVMFuzzerInitialize(NULL, NULL);
        LLVMFuzzerTestOneInput(buf, s);
        free(buf);
        fclose(f);
    }
    return 0;
}
