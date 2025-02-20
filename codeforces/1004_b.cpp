#include <stdio.h>
#include <stdlib.h>

int a[1002];
int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

bool check(int *a, int n)
{
  int current = a[0];
  int count = 0;
  
  for(int i = 0; i < n; i++){
    if(a[i] == current) count++;
    else{
      if(count == 1) return false;
      else if(count == 2) return check(&a[2], n - 2);
      else{
	for (int j = 2; j < count; j++){
	  a[j]++;
	}
	
	return check(&a[2], n-2);
      }
    }
  }

  return true;

}


int main()
{
  int count = 0;
  scanf("%d", &count);

  for (int i = 0; i < count; i++)
  {
    int n = 0;
    scanf("%d", &n);
    for (int j = 0; j < n; j++)
    {
      scanf("%d", &a[j]);
    }
    qsort(a, n, sizeof(int), compare);
    
    if(check(a, n))
      printf("YES\n");
    else
      printf("NO\n");
  }

  return 0;
}
