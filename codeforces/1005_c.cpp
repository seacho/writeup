#include <stdio.h>
#include <stdlib.h>
long long a[200005];
long long posPrefix[200005];
long long negSuffix[200005];
int main(){
    int t;
    if(scanf("%d", &t) != 1) return 1;
    while(t--){
        int n;
        scanf("%d", &n);
        for (int i = 0; i < n; i++){
            scanf("%lld", &a[i]);
        }
        
        posPrefix[0] = 0;
        for (int i = 0; i < n; i++){
            if(a[i] > 0)
                posPrefix[i+1] = posPrefix[i] + a[i];
            else
                posPrefix[i+1] = posPrefix[i];
        }
        
        negSuffix[n] = 0;
        for (int i = n-1; i >= 0; i--){
            long long coin = (a[i] < 0) ? - (long long) a[i] : 0;
            negSuffix[i] = negSuffix[i+1] + coin;
        }
        

        long long ans = 0;
        for (int j = 0; j <= n; j++){
            long long candidate = posPrefix[j] + negSuffix[j];
            if(candidate > ans)
                ans = candidate;
        }
        
        printf("%lld\n", ans);
        
    }
    return 0;
}
