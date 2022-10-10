#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

void printArray(int* arr, size_t arraySize) 
{
    for (int i = 0; i < arraySize; ++i) {
        printf("%d, ", arr[i]);    
    }
    printf("\n");
}

void getPrimes(int* p, int* q, int min, int max)
{
    printf("min: %d, max: %d\n", min, max);
    int* arr = (int*)malloc((max - min) * sizeof(int));
    short* boolArr = (short*)malloc((max - min) * sizeof(short));
    for (int i = 0; i < max - min; i++) {
        arr[i] = i;
    }
    memset(boolArr, 0, sizeof(boolArr));
    printArray(arr, max - min);
    for (int i = 0; i < max - min; ++i) {
        
    }
    
}

int main()
{
    int p, q;
    getPrimes(&p, &q, 100, 200);

}