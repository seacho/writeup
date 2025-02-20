#include<bits/stdc++.h>
using namespace std;
typedef long long ll;
#define debug(x) cout << #x << " = " << x << "\n";
#define vdebug(a) cout << #a << " = "; for(auto x: a) cout << x << " "; cout << "\n";
mt19937 rng(chrono::steady_clock::now().time_since_epoch().count());
int uid(int a, int b) { return uniform_int_distribution<int>(a, b)(rng); }
ll uld(ll a, ll b) { return uniform_int_distribution<ll>(a, b)(rng); }

const int W = 30;

void solve(){
    int n, q;
    cin >> n >> q;

    vector<int> a(n);
    for (int &x : a) cin >> x;
    
    vector<int> pre(n + 1);
    pre[0] = a[0];
    for (int i = 1; i < n; i++){
        pre[i] = pre[i - 1] ^a[i];
    }

    vector<array<int, W>> last(n);
    for (int i = 0; i < n; i++){
            fill(last[i].begin(), last[i].end(), 0);
        if (i > 0) last[i] = last[i - 1];
        last[i][__lg(a[i])] = i;

        for (int j = W - 2; j >= 0; j--){
            last[i][j] = max(last[i][j], last[i][j + 1]);
        }
    }

    while (q--) {
        int x;
        cin >> x;

        int idx = n - 1;
        while (idx >= 0 && x > 0){
            int msb = __lg(x);

            int nxt = last[idx][msb];
            x ^= pre[idx] ^ pre[nxt];
            idx = nxt;
            if (nxt == -1 || a[nxt] > x) break;

            x ^= a[nxt];
            idx--;
        }

        cout << n - idx - 1 << "\n";
    }
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(0);
    cout.tie(0);
    
    int t;
    cin >> t;
    while (t--) solve();
}
