#include <stdio.h>

int solve(const char *s, int n) {
    if(n == 0)
        return 0;
    int moves = 0;

    for (int i = 0; i < n - 1; i++) {
        if (s[i] != s[i+1])
            moves++;
    }

    if (s[0] == '1')
        moves++;
    return moves;
}

char a[1003];
int main()
{
  int t;
  scanf("%d", &t);
  while(t--){
    int n;
    scanf("%d", &n);
    scanf("%s", a);
    printf("%d\n",solve(a, n));
  }

  return 0;
}
