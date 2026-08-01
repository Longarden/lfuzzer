#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#ifndef DT_THISPROCNUM
#define DT_THISPROCNUM 0
#endif
typedef uint64_t utype;

const char* route(int64_t tag, long *slot){
  utype t=(utype)tag;
  if(t < DT_NUM){ *slot=tag; return "1.NUM(정상범위)"; }
  if(tag>=DT_LOPROC && tag<DT_LOPROC+DT_THISPROCNUM){ *slot=tag-DT_LOPROC+DT_NUM; return "2.PROC"; }
  if((utype)DT_VERSIONTAGIDX(tag) < DT_VERSIONTAGNUM){ *slot=DT_VERSIONTAGIDX(tag)+DT_NUM+DT_THISPROCNUM; return "3.VERSION"; }
  if((utype)DT_EXTRATAGIDX(tag) < DT_EXTRANUM){ *slot=DT_EXTRATAGIDX(tag)+DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM; return "4.EXTRA(범인)"; }
  if((utype)DT_VALTAGIDX(tag) < DT_VALNUM){ *slot=DT_VALTAGIDX(tag)+DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM; return "5.VAL"; }
  if((utype)DT_ADDRTAGIDX(tag) < DT_ADDRNUM){ *slot=DT_ADDRTAGIDX(tag)+DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM; return "6.ADDR"; }
  *slot=-1; return "버려짐(IGNORED)";
}

void show(int64_t tag, const char* label){
  int32_t lo=(int32_t)tag;
  int32_t aliased=(lo<<1)>>1;
  long slot; const char* r=route(tag,&slot);
  printf("%-22s tag=0x%016llx | (i32)=0x%08x | <<1>>1=0x%08x | EXTRAIDX=%llu | -> %-16s slot=%ld\n",
         label,(unsigned long long)tag,(uint32_t)lo,(uint32_t)aliased,
         (unsigned long long)(utype)DT_EXTRATAGIDX(tag), r, slot);
}

int main(void){
  printf("=== 진짜 EXTRA 태그 (양수, 원래 의도) ===\n");
  show(0x7fffffff,"DT_FILTER");
  show(0x7ffffffe,"(0x7ffffffe)");
  show(0x7ffffffd,"DT_AUXILIARY");
  show(0x7ffffffc,"0x7ffffffc(경계밖)");
  printf("\n=== 음수 쌍둥이 (상위 bit만 다름) ===\n");
  show(-1,"-1");
  show(-2,"-2");
  show(-3,"-3");
  show(-4,"-4");
  printf("\n=== 상위 32비트가 쓰레기여도 무시되나 ===\n");
  show((int64_t)0xDEADBEEFFFFFFFFFULL,"0xDEADBEEF_FFFFFFFF");
  show((int64_t)0x123456787FFFFFFFULL,"0x12345678_7FFFFFFF");
  printf("\n=== 진짜 버려지는 음수들 ===\n");
  show((int64_t)0x8000000000000000ULL,"INT64_MIN");
  show((int64_t)0x8000000000000001ULL,"0x8..0001");
  printf("\n=== 참고: 정상/경계 태그 ===\n");
  show(5,"DT_STRTAB(5)");
  show(21,"DT_DEBUG(21)");
  show(0x6ffffff0,"DT_VERSYM");
  show(0x6ffffd00,"DT_VALRNGLO");
  return 0;
}
