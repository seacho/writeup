#include <stdio.h>
#include <string.h>

int a[200000];
int res[10000];

int main()
{
  int count = 0;
  scanf("%d", &count);
  for (int i = 0; i < count; i++)
  {
    int x,y;
    scanf("%d",&x);
    scanf("%d",&y);
    int delta = x + 1 - y;
    if (delta < 0 or delta % 9 != 0)
    {
      printf("NO\n");
    }
    else{
      int k = delta / 9;
      if (k == 0)
	printf("YES\n");
      else{
	if (x >= 9 * k)
	  printf("YES\n");
        else
          printf("NO\n");
      }
    }
  }
}
