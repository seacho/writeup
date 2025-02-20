#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOD 998244353


#define MAXN 200005

typedef struct {
    int n;
    long long *tree;
} BIT;


BIT *createBIT(int n) {
    BIT *bit = (BIT *) malloc(sizeof(BIT));
    bit->n = n;
    bit->tree = (long long *) calloc(n+1, sizeof(long long));
    return bit;
}

void updateBIT(BIT *bit, int pos, long long value) {
    for(; pos <= bit->n; pos += pos & -pos) {
        bit->tree[pos] = (bit->tree[pos] + value) % MOD;
    }
}

long long queryBIT(BIT *bit, int pos) {
    long long res = 0;
    for(; pos > 0; pos -= pos & -pos) {
        res = (res + bit->tree[pos]) % MOD;
    }
    return res;
}


long long modExp(long long base, long long exp) {
    long long result = 1;
    base %= MOD;
    while(exp > 0) {
        if(exp & 1)
            result = (result * base) % MOD;
        base = (base * base) % MOD;
        exp >>= 1;
    }
    return result;
}

int main(){
    int t;
    if(scanf("%d", &t) != 1)
        return 1;

    long long *pow2 = (long long *) malloc((MAXN+1) * sizeof(long long));
    pow2[0] = 1;
    for (int i = 1; i <= MAXN; i++){
        pow2[i] = (pow2[i-1] * 2) % MOD;
    }

    long long inv2 = modExp(2, MOD-2);
    
    while(t--){
        int n;
        if(scanf("%d", &n) != 1)
            return 1;
        
        int *a = (int *) malloc(n * sizeof(int));
        for (int i = 0; i < n; i++){
            scanf("%d", &a[i]);
        }
        

        int *P2 = (int *) malloc((n+1) * sizeof(int));
        P2[0] = 0;
       
        for (int i = 1; i <= n; i++){
            P2[i] = P2[i-1] + (a[i-1] == 2);
        }
        

        BIT *bitSum = createBIT(n);
        BIT *bitCount = createBIT(n);
        
        long long ans = 0;

        for (int i = 1; i <= n; i++){
            if(a[i-1] == 1){
                long long val = modExp(inv2, P2[i]);
                updateBIT(bitSum, i, val);
                updateBIT(bitCount, i, 1);
            }
            else if(a[i-1] == 3){
                int x = P2[i-1];
                long long sumVal = queryBIT(bitSum, i-1);
                long long cnt = queryBIT(bitCount, i-1);
                long long contrib = ( (pow2[x] * sumVal) % MOD - cnt ) % MOD;
                if(contrib < 0) contrib += MOD;
                ans = (ans + contrib) % MOD;
            }

        }
        
        printf("%lld\n", ans);
        
        free(a);
        free(P2);
        free(bitSum->tree); free(bitSum);
        free(bitCount->tree); free(bitCount);
    }
    free(pow2);
    return 0;
}
