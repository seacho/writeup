#include <stdio.h>
#include <string.h>



int main()
{
  int count = 0;
  char a[110][110];
  scanf("%d", &count);
  for (int i = 0; i < count; i++) {
    scanf("%s", a[i]);
  }
  for (int i = 0; i < count; i++){
    int is_1 = 0;
    for(int j = 0; j < strlen(a[i])-1; j++){
      if(a[i][j] == a[i][j + 1]){
	is_1 = 1;
	break;
      }
    }
    if (is_1 == 1){
      printf("%d\n",1);
    }
    else{
      printf("%d\n",strlen(a[i]));
    }
  }
  return 0;
}
