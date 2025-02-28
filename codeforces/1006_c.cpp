#include <stdio.h>

void solve() {
    int n;
    unsigned int x;
    scanf("%d %u", &n, &x);
    
    // 构造一个满足条件的数组
    for (int i = 0; i < n - 1; i++) {
        printf("%d ", i); // 使用从 0 到 n-2 的数
    }
    // 计算最后一个元素，使得整个数组的按位或等于 x
    unsigned int last = x;
    for (int i = 0; i < n - 1; i++) {
        last ^= i; // 计算最后一个元素，使得整体的 OR 结果仍然是 x
    }
    printf("%u\n", last);
}

int main() {
    int t;
    scanf("%d", &t);
    while (t--) {
        solve();
    }
    return 0;
}
