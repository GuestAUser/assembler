#include <stdio.h>
#include <string.h>

int check_password(const char *candidate) {
    return candidate[0] == 'o' &&
           candidate[1] == 'p' &&
           candidate[2] == 'e' &&
           candidate[3] == 'n' &&
           candidate[4] == '-' &&
           candidate[5] == 's' &&
           candidate[6] == 'e' &&
           candidate[7] == 's' &&
           candidate[8] == 'a' &&
           candidate[9] == 'm' &&
           candidate[10] == 'e' &&
           candidate[11] == '\0';
}

int main(void) {
    char input[64];

    printf("Password: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';

    if (check_password(input)) {
        puts("ACCESS GRANTED");
        puts("Secret: the vault code is 0000.");
        return 0;
    }

    puts("ACCESS DENIED");
    return 1;
}
