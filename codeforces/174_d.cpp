#include <stdio.h>
#include <string.h>

int main() {
    int t;
    scanf("%d", &t);
    while (t--) {
        char s[500001];
        int a, b, ab, ba;
        scanf("%s", s);
        scanf("%d %d %d %d", &a, &b, &ab, &ba);

        int len = strlen(s);
        int countA = 0, countB = 0, countAB = 0, countBA = 0;
        int i = 0;

        while (i < len) {
            if (s[i] == 'A') {
                if (i + 1 < len && s[i + 1] == 'B') {
                    countAB++;
                    i += 2;
                } else {
                    countA++;
                    i++;
                }
            } else if (s[i] == 'B') {
                if (i + 1 < len && s[i + 1] == 'A') {
                    countBA++;
                    i += 2;
                } else {
                    countB++;
                    i++;
                }
            }
        }

        if (countA <= a && countB <= b && countAB <= ab && countBA <= ba) {
            printf("YES\n");
        } else {
            printf("NO\n");
        }
    }
    return 0;
}
