/* Fixture vulnerable: command injection vía system() con datos de argv.
 * Usado por los tests de M1/M2/M4. NO es código de producción. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Punto de entrada: el host viene directo de argv sin sanitizar. */
void handle_ping_input(char *host) {
    char cmd[256];
    /* VULN: interpolación directa de input del usuario en un comando shell. */
    sprintf(cmd, "ping -c 1 %s", host);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "uso: %s <host>\n", argv[0]);
        return 1;
    }
    handle_ping_input(argv[1]);
    return 0;
}
