#include <stdio.h>
#include <stdlib.h>
#include <string.h>
long long a[200005];

long long  solve(const long long *s,int l, int r) {
  long long max = 0;
  for (int i = l; i <= r; i++)
  {
    long long tmp;
    if (a[i] < 0){
      tmp = 0 - a[i] + solve(s, l, i - 1);
    }
    else
    {
      tmp = a[i] + solve(s, i+1, r);
    }
    max = (tmp > max)?tmp:max;
  }
  return max;
}

int main()
{
  int t;
  scanf("%d", &t);
  while(t--){
    int n;
    scanf("%d", &n);
    for (int i = 0; i < n; i++)
      scanf("%lld", &a[i]);
    printf("%lld\n", solve(a, 0, n - 1));
  }

  return 0;
}
