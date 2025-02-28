#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef long long ll;
void solve() {
    int t;
    scanf("%d", &t);
    while (t--) {
        ll  n, x;
        ll k;
        scanf("%lld %lld %lld", &n, &x, &k);
        
        char *s = (char*)malloc(n + 1);
        ll *cnt=(ll*)calloc(2*(n+1), sizeof(ll));
       
        scanf("%s", s);
        ll ans = 0;

        ll i = 0;

        ll o_x = x;
        ll end_x = o_x;
        while(i < n){
            cnt[end_x + n + 1]++;
            if(s[i] == 'L')
                end_x--;
            if(s[i] == 'R')
                end_x++;
            i++;
        }

        ll d = k / n;
        i = 0;
        
        while(i < d)
        {

            ans += cnt[0 - o_x + x + n + 1];
            o_x = end_x;
            end_x += (end_x - o_x);

            i++;
        }
        ll o = n - d * k;
        i = 0;
        while(i < o){
            
            if(s[i] == 'L')
                end_x--;
            if(s[i] == 'R')
                end_x++;
            if (end_x == 0)
                ans++;
            i++;
        }
        
        free(s);
        free(cnt);
        printf("%lld\n", ans);
    }
}

int main() {
    solve();
    return 0;
}
