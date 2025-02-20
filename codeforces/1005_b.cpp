#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int a[200005];
unsigned char b[200005];

void solve(const int *s, int n) {
  memset(b, 0, sizeof(b));
  int l = -1, r = -1, delt = 0, an_l = -1, an_r = -1;

  for (int i = 0; i < n; i++)
    b[s[i]] += 1;

  for (int i = 0; i < n; i++){
    if(b[s[i]] == 1 || b[s[i]] == 0){
      if (l == -1)
	l = i;
      r = i;
    }
    else{
      l = -1;
    }
    if (l != -1 && r - l >= delt)
    {
      an_l = l;
      an_r = r;
      delt = r - l;
    }
  }
  if (an_l != -1 )
    printf("%d %d\n", an_l + 1, an_r + 1);
  else
    printf("0\n");
}


int main()
{
  int t;
  scanf("%d", &t);
  while(t--){
    int n;
    scanf("%d", &n);
    for (int i = 0; i < n; i++)
      scanf("%d", &a[i]);
    solve(a, n);
  }

  return 0;
}
