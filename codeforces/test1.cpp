#include <stdio.h>
#include <limits.h>

int main(){
    int t;
    scanf("%d", &t);
    while(t--){
        int n;
        scanf("%d", &n);
        int a[2100];
        for (int i = 0; i < n; i++){
            scanf("%d", &a[i]);
        }
        
        // 记录最佳区间 [best_l, best_r] 以及对应的最小 delta
        int best_l = 0, best_r = 0;
        int best_delta = 0;  // 初始区间长度为 1时 delta = 0
        
        // 枚举所有区间 [l, r] (0-indexed)
        for (int l = 0; l < n; l++){
            int delta = 0; // 对应区间 [l, l] 时，delta = 0
            // 更新答案（区间长度为1时，delta=0）
            if (delta < best_delta) {
                best_delta = delta;
                best_l = l;
                best_r = l;
            }
            for (int r = l + 1; r < n; r++){
                // 对于每个新加入的 a[r]，比较其与 a[l] 的大小
                if (a[r] > a[l])
                    delta++;  // 原来 (l, r) 形成逆序对（a[l] > a[r]）在移位后不再存在，反之如果 a[r] > a[l]则会新增逆序对
                else if (a[r] < a[l])
                    delta--;  // 消除一个逆序对
                // 如果当前区间 [l, r] 得到的 delta 更小，则更新最佳答案
                if (delta < best_delta) {
                    best_delta = delta;
                    best_l = l;
                    best_r = r;
                }
            }
        }
        
        // 输出时转换为 1-indexed
        printf("%d %d\n", best_l + 1, best_r + 1);
    }
    return 0;
}
