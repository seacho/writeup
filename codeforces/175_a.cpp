#include <stdio.h>

typedef long long ll;

void solve() {
    int t;
    scanf("%d", &t);
    while (t--) {
        ll n;
        scanf("%lld", &n);
        ll d = n / 15;
        printf("%lld\n", d * 3 + (((n - d * 15) >= 3)? 3: (n - d * 15)+1) ); 
    }
}

int main() {
    solve();
    return 0;
}
