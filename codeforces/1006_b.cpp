#include <stdio.h>
#include <string.h>
#include <stdlib.h>
char a[200003];
//int up[200003];
//int down[2000]


int main() {
    int t;
    scanf("%d", &t);
    while (t--) {
        int n;
        scanf("%d", &n);
        scanf("%s", a);
        long long d = 0;

        long long  count = 0;
        long long down_count = 0;
        for(int i = n-1; i >= 0; i--){
            if (a[i] == '-'){
                //up[i] = count;        
                count++;
            }
            else{
                //up[i] = count;
                down_count++;
            }
        }
        //printf("%d\n", count);


        d += down_count *(count/2) * (count - count/2);      

          
        
        printf("%lld\n", d);
    }
    return 0;
}
