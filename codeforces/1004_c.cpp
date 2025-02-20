#include <bits/stdc++.h>
using namespace std;
 
// Structure for DP state.
struct State {
    int pos;    // current digit position (positions 1..L-1; note pos 0 = ones digit is fixed)
    int used;   // how many operations (ones) have been used so far
    int carry;  // carry coming into this digit
    bool found; // whether a digit 7 has been seen already in a lower digit
};
 
// We need a hash for our state.
struct StateHash {
    size_t operator()(const State &s) const {
        size_t res = 17;
        res = res * 31 + hash<int>()(s.pos);
        res = res * 31 + hash<int>()(s.used);
        res = res * 31 + hash<int>()(s.carry);
        res = res * 31 + hash<int>()(s.found ? 1 : 0);
        return res;
    }
};
 
bool operator==(const State &a, const State &b) {
    return a.pos == b.pos && a.used == b.used && a.carry == b.carry && a.found == b.found;
}
 
// Global variables for the DP: 
//   g_k: number of operations (the fixed total we must use)
//   L: number of digit positions we simulate (we choose L = 12, which is enough for n up to 1e9 plus extra carry).
//   baseDigits: digits of (n - k) (positions 0=ones, 1=tens, …)
int g_k, L;
vector<int> baseDigits;
 
// memoization cache for DP
unordered_map<State, bool, StateHash> memo;
 
// DP function: processes positions pos (starting at 1) up to L-1.
// Parameters:
//   pos: current digit position (pos = 0 is the ones digit, already “fixed”)
//   used: number of operations (ones added) used so far (we must have sum x = g_k overall)
//   carry: current carry
//   found: whether any digit 7 has been seen in any digit processed so far.
bool dp(int pos, int used, int carry, bool found) {
    State s { pos, used, carry, found };
    if (memo.find(s) != memo.end())
        return memo[s];
    if (pos >= L) {
        // Process any remaining carry: its digits get appended.
        int c = carry;
        bool finalFound = found;
        while(c > 0) {
            int d = c % 10;
            if(d == 7) finalFound = true;
            c /= 10;
        }
        memo[s] = finalFound;
        return finalFound;
    }
    int a = baseDigits[pos];  // digit of (n - k) at position pos
    int remain = g_k - used;
    // Try all possible contributions x at this digit (0 <= x <= remain)
    for (int x = 0; x <= remain; x++) {
        int total = a + x + carry;
        int d = total % 10;
        int newCarry = total / 10;
        bool newFound = found || (d == 7);
        if (dp(pos + 1, used + x, newCarry, newFound))
        {
            memo[s] = true;
            return true;
        }
    }
    memo[s] = false;
    return false;
}
 
// For a given n and candidate k (number of operations), check if it is possible
// to choose k allowed operations (i.e. numbers of the form 10^d - 1) so that the
// final number M = n + (sum of operations) contains at least one digit 7.
bool canAchieve(long long n, int k) {
    // Let M = n + S where S = (sum_{i} (10^(d_i) - 1)) = (X - k)
    // Then M = n - k + X.
    // The ones digit of M is (n - k) % 10 (since X adds only in positions >= 1).
    int ones = (int)((n - k) % 10);
    bool initFound = (ones == 7);
    // Set L = 12 (this many digit positions will cover n up to 10^9 plus extra)
    L = 12;
    baseDigits.assign(L, 0);
    long long baseVal = n - k;
    for (int pos = 0; pos < L; pos++){
        baseDigits[pos] = (int)(baseVal % 10);
        baseVal /= 10;
    }
    g_k = k;
    memo.clear();
    // Start the DP from pos = 1 (tens digit), with used = 0, carry = 0, and found = initFound.
    return dp(1, 0, 0, initFound);
}
 
// A simple helper to check if a number (given as long long) contains digit 7.
bool hasSeven(long long x) {
    if(x < 0) x = -x;
    while(x) {
        if(x % 10 == 7) return true;
        x /= 10;
    }
    return false;
}
 
// Main function: for each test case, if n already contains digit '7', output 0.
// Otherwise, try k = 1..10 and output the smallest k for which canAchieve(n, k) is true.
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
 
    int t;
    cin >> t;
    while(t--){
        long long n;
        cin >> n;
        if(hasSeven(n)){
            cout << 0 << "\n";
            continue;
        }
        int ans = -1;
        for (int k = 1; k <= 10; k++){
            if(canAchieve(n, k)){
                ans = k;
                break;
            }
        }
        // By problem statement an answer always exists for k<=10.
        if(ans == -1) ans = 10;
        cout << ans << "\n";
    }
    return 0;
}
