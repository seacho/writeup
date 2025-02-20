#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int a[200005];
int b[200005];
int c[200005][30];

int main()
{
  int t;
  scanf("%d", &t);
  while(t--){
    int n, q, x;
    scanf("%d %d", &n, &q);
    for(int i = 0; i < n; i++){
      scanf("%d", &a[i]);
    }
    b[n-1] = a[n-1];
    for(int i = n - 2; i >=0; i--){
      b[i] = b[i+1] ^ a[i];
    }
    
    
    while(q--){
      scanf("%d", &x);
      int ans = 0;
      int l = 0, r = n-1;
      while(l < r)
      {
	int mid = (l + r)/2;
        if(c[mid] <= x){
	  r = mid;
	}else{
	  l = mid;
	}
	
      }
      
      printf("%d ", ans);
    }
    
    
    printf("\n");
  }

}
