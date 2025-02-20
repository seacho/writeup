#include <stdio.h>

int a[105];
int main()
{
  int t;
  scanf("%d", &t);
  while(t--){
    int n;
    scanf("%d", &n);
    for (int i = 0; i < n - 2; i++)
    {
      scanf("%d", &a[i]);
    }
    const char *ans = "YES\n";
    for (int i = 0; i < n - 4; i++)
    {
      if(a[i] == 1 && a[i+1] == 0 && a[i+2] == 1){
	ans = "NO\n";
	break;
      }
    }
    printf("%s", ans);
    
  }

  return 0;
}
