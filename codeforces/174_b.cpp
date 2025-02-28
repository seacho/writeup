#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int a[700][700];
int has_color[700*700];
int has_bad[700*700];
int main() {
    int t;
    scanf("%d", &t);
    while (t--) {
        int n, m;
        scanf("%d %d", &n, &m);
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                scanf("%d", &a[i][j]);
        memset(has_color, 0, sizeof(has_color));
        memset(has_bad, 0, sizeof(has_bad));
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++){
                has_color[a[i][j] - 1] = 1;
                if (i + 1 < n && a[i][j] == a[i+1][j])
                    has_bad[a[i][j] - 1] = 1;
                if (j + 1 < m && a[i][j] == a[i][j+1])
                    has_bad[a[i][j] - 1] = 1;
            }
        int ans = 0;
        int max = 0;
        for(int i = 0; i < n*m; i++){
            ans += has_color[i];
            ans += has_bad[i];
            if (max < has_bad[i])
                max = has_bad[i];
        }
        ans = ans - 1 - max;
           
        printf("%d\n", ans);
    }
    return 0;
}
