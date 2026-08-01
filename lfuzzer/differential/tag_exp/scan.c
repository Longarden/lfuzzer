#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#ifndef DT_THISPROCNUM
#define DT_THISPROCNUM 0
#endif
typedef uint64_t U;

int route(int64_t tag){         // 0=NUM 1=PROC 2=VERSION 3=EXTRA 4=VAL 5=ADDR -1=IGNORED
  U t=(U)tag;
  if(t < DT_NUM) return 0;
  if(tag>=DT_LOPROC && tag<DT_LOPROC+DT_THISPROCNUM) return 1;
  if((U)DT_VERSIONTAGIDX(tag) < DT_VERSIONTAGNUM) return 2;
  if((U)DT_EXTRATAGIDX(tag) < DT_EXTRANUM) return 3;
  if((U)DT_VALTAGIDX(tag) < DT_VALNUM) return 4;
  if((U)DT_ADDRTAGIDX(tag) < DT_ADDRNUM) return 5;
  return -1;
}
const char* NAME(int r){
  switch(r){case 0:return "정상칸(NUM)";case 1:return "PROC칸";case 2:return "VERSION칸";
  case 3:return "EXTRA칸(FILTER/AUX)";case 4:return "VAL칸";case 5:return "ADDR칸";default:return "버려짐(IGNORED)";}
}
int main(void){
  // 부호확장된 int32 계열 전수 스캔: v=0..0xffffffff, tag=(int64)(int32)v
  // (상위32비트는 EXTRA/VAL/ADDR/VERSION 분기에서 어차피 무시됨)
  long long start=0; int prev=route((int64_t)(int32_t)0);
  for(long long v=1; v<=0xffffffffLL; v++){
    int r=route((int64_t)(int32_t)(uint32_t)v);
    if(r!=prev){
      printf("0x%08llx .. 0x%08llx  -> %s\n",(unsigned long long)start,(unsigned long long)(v-1),NAME(prev));
      start=v; prev=r;
    }
  }
  printf("0x%08llx .. 0xffffffff  -> %s\n",(unsigned long long)start,NAME(prev));
  return 0;
}
