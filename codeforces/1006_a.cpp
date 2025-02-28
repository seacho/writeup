#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main() {
    int t;
    scanf("%d", &t);
    while (t--) {
        int n, k, p;
        scanf("%d %d %d", &n, &k, &p);
        if (k < 0)
            k = 0 - k;
        int d = k/p;
        int r = k%p;
        if (r != 0)
            d += 1;
        if (d > n)
            d = -1;
        printf("%d\n", d);
    }
    return 0;
}
