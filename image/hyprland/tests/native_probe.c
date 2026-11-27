/* Disposable qualification fixture: record any native code load before API checks. */
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) static void record_load(void) {
    const char *path = getenv("SYMBI_NATIVE_LOAD_MARKER");
    if (path == NULL)
        return;
    FILE *output = fopen(path, "w");
    if (output == NULL)
        return;
    fputs("native constructor executed\n", output);
    fclose(output);
}

struct lua_State;
int luaopen_symbi_probe(struct lua_State *state) {
    (void)state;
    return 0;
}
