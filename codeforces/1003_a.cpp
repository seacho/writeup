#include <stdio.h>
#include <string.h>

int main()
{
  int count = 0;
  char a[100][11];
  scanf("%d", &count);
  for (int i = 0; i < count; i++) {
    scanf("%s", a[i]);
    a[i][strlen(a[i]) - 2] = 'i';
    a[i][strlen(a[i]) - 1] = '\x00';
  }
  for (int i = 0; i < count; i++){
    printf("%s\n", a[i]);

  }
}
