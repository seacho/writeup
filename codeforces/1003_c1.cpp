#include <stdio.h>
#include <string.h>

int a[200000];
int res[10000];

int main()
{
  int count = 0;
  scanf("%d", &count);
  
  for (int i = 0; i < count; i++) {
    int m, n;
    scanf("%d", &m);
    scanf("%d", &n);
    for(int j = 0; j < m; j++)
      scanf("%d", &a[j]);

    scanf("%d", &n);
    for(int j = 0; j < m; j++){
      
    }


  }
  for (int i = 0; i < count; i++){
    if (res[i] == 1){
      printf("NO\n");
    }
    else{
      printf("YES\n");
    }
  }

  return 0;
}
