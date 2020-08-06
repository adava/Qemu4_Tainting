// C program to illustrate 
// fgets() 
#include <stdio.h>
#include <string.h> 
#define MAX 15 
int main() 
{ 
    int a=95;
    char buf[MAX];
    char buf2[MAX];
    int b=96;
    fgets(buf, MAX, stdin); 
    printf("a=%d, b=%d \t buf %p: %s\n", a, b, buf, buf);
    buf2[0] = buf[0];
    //strcpy(buf2,buf);
    //printf("buf2 %p: %s\n", buf2, buf2); 
    return 0; 
}
