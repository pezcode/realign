#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <windows.h>

#define HDR3264(NTH, Field) (IsPE64(NTH) ? (((IMAGE_NT_HEADERS64 *)NTH)->Field) : (((IMAGE_NT_HEADERS32 *)NTH)->Field))

static const DWORD FILEALIGNMENT_DOWN = 0x200;

bool GetNTHeader(void * pMap, DWORD dwSize, IMAGE_DOS_HEADER ** opDosH, IMAGE_NT_HEADERS ** opNTH, IMAGE_SECTION_HEADER ** opSecs, WORD * onSecs);
IMAGE_NT_HEADERS * GetNTHeader(void * pMap);
DWORD SizeOfPEHeader(const IMAGE_NT_HEADERS * pNTH);
bool IsPE64(const IMAGE_NT_HEADERS * pNTH);
DWORD RVAToOffset(DWORD dwRVA, const void * pMap);
DWORD StripSection(void * pMap, DWORD dwFsize, DWORD nSection);
void FixVSizes(IMAGE_NT_HEADERS * pNTH);
DWORD AlignUp(DWORD dwBadSize, DWORD dwAlignment);
DWORD AlignDown(DWORD dwBadSize, DWORD dwAlignment);
bool ValidFileAlignment(DWORD dwAlign);

#endif
