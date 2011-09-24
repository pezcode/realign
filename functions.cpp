#include "functions.h"

#include <windows.h>
#include <cstddef> // offsetof

bool GetNTHeader(void * pMap, DWORD dwSize, IMAGE_DOS_HEADER ** opDosH, IMAGE_NT_HEADERS ** opNTH, IMAGE_SECTION_HEADER ** opSecs, WORD * onSecs)
{
IMAGE_DOS_HEADER * pDosH;
IMAGE_NT_HEADERS * pNTH;

	pDosH = (IMAGE_DOS_HEADER *)pMap;
	if(dwSize > sizeof(IMAGE_DOS_HEADER) && pDosH->e_magic == IMAGE_DOS_SIGNATURE && pDosH->e_lfanew > 0 && pDosH->e_lfanew < 0x10000000)
	{
		pNTH = (IMAGE_NT_HEADERS *)((ULONG_PTR)pMap + pDosH->e_lfanew);
		if(dwSize >= (pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS)) && pNTH->Signature == IMAGE_NT_SIGNATURE)
		{
			if(pNTH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
			   pNTH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				if(dwSize >= (pDosH->e_lfanew + SizeOfPEHeader(pNTH)))
				{
					if(opDosH) *opDosH = pDosH;
					if(opNTH)  *opNTH  = pNTH;
					if(opSecs) *opSecs = IMAGE_FIRST_SECTION(pNTH);
					if(onSecs) *onSecs = pNTH->FileHeader.NumberOfSections;
					return true;
				}
			}
		}
	}

	return false;
}

IMAGE_NT_HEADERS * GetNTHeader(void * pMap)
{
IMAGE_DOS_HEADER * pDosH;
IMAGE_NT_HEADERS * pNTH;

	pDosH = (IMAGE_DOS_HEADER *)pMap;
	if(pDosH->e_magic == IMAGE_DOS_SIGNATURE && pDosH->e_lfanew > 0 && pDosH->e_lfanew < 0x10000000)
	{
		pNTH = (IMAGE_NT_HEADERS *)((ULONG_PTR)pMap + pDosH->e_lfanew);
		if(pNTH->Signature == IMAGE_NT_SIGNATURE)
		{
			if(pNTH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
			   pNTH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				return pNTH;
			}
		}
	}

	return 0;
}

DWORD SizeOfPEHeader(IMAGE_NT_HEADERS * pNTH)
{
	return (offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pNTH->FileHeader.SizeOfOptionalHeader + (pNTH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}

bool IsPE64(IMAGE_NT_HEADERS * pNTH)
{
	return (pNTH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

DWORD RVAToOffset(DWORD dwRVA, void * pMap)
{
IMAGE_NT_HEADERS *     pNTH;
IMAGE_SECTION_HEADER * SectionTable;
DWORD                  VAddress, VSize, ROffset, RSize, UpperBound;
unsigned int           i;

	pNTH = (IMAGE_NT_HEADERS *)((ULONG_PTR)pMap + ((IMAGE_DOS_HEADER *)pMap)->e_lfanew);
	SectionTable = IMAGE_FIRST_SECTION(pNTH);

	if(dwRVA < SectionTable[0].VirtualAddress) // RVA points to header
		return dwRVA;

	for(i=0; i < pNTH->FileHeader.NumberOfSections; i++)
	{
		VAddress = SectionTable[i].VirtualAddress;
		VSize    = AlignUp(SectionTable[i].Misc.VirtualSize, pNTH->OptionalHeader.SectionAlignment);
		ROffset  = SectionTable[i].PointerToRawData;
		RSize    = AlignUp(SectionTable[i].SizeOfRawData, pNTH->OptionalHeader.FileAlignment);

		UpperBound = (RSize < VSize) ? RSize : VSize;

		if((dwRVA >= VAddress) && (dwRVA < (VAddress + UpperBound)))
		{
			return (dwRVA - VAddress + ROffset);
		}
	}

	return 0;
}

DWORD StripSection(void * pMap, DWORD dwFsize, DWORD nSection)
{
IMAGE_NT_HEADERS *     pNTH;
IMAGE_SECTION_HEADER * pSH, * pSHC;
DWORD                  dwNewFsize;
DWORD                  Diff;
unsigned int           i;

	pNTH = GetNTHeader(pMap);

	// section doesn't exist / only one section
	if(nSection >= pNTH->FileHeader.NumberOfSections || pNTH->FileHeader.NumberOfSections == 1)
		return 0;

	pSHC = IMAGE_FIRST_SECTION(pNTH); // used in loop
	pSH  = &pSHC[nSection]; // section to delete

	pNTH->FileHeader.NumberOfSections--;

	if(nSection == pNTH->FileHeader.NumberOfSections)
	{	// last section -> truncate at section start
		dwNewFsize = pSH->PointerToRawData; // ????

		pSH--;
		if(IsPE64(pNTH)){
			if(pSH->Misc.PhysicalAddress)
				((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->Misc.VirtualSize;
			else // WATCOM is always a bit special >:-)
				((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->SizeOfRawData;
		}
		else{
			if(pSH->Misc.PhysicalAddress)
				((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->Misc.VirtualSize;
			else
				((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->SizeOfRawData;
		}
	}
	else // not the last section
	{
		if(pSH->SizeOfRawData != 0)
		{
			Diff = AlignUp(pSH->SizeOfRawData, HDR3264(pNTH, OptionalHeader.FileAlignment));

			dwNewFsize = dwFsize - Diff;

			// copy section(s) after this section to the start of this section
			memcpy((void *)((ULONG_PTR)pMap + pSH->PointerToRawData), (void *)((ULONG_PTR)pMap + pSH->PointerToRawData + Diff), dwFsize - pSH->PointerToRawData - Diff);

			for(i=0; i <= pNTH->FileHeader.NumberOfSections; i++)
			{
				if(pSHC->PointerToRawData >= (pSH->PointerToRawData + Diff))
					pSHC->PointerToRawData -= Diff;
				pSHC++;
			}			
		}

		// fix section header
		if(nSection == 0)
		{
			pSH->SizeOfRawData = 0;	
			pNTH->FileHeader.NumberOfSections++;
		}
		else
		{
			(pSH-1)->Misc.VirtualSize += pSH->Misc.VirtualSize;
			memcpy(pSH, (pSH+1), sizeof(IMAGE_SECTION_HEADER) * (pNTH->FileHeader.NumberOfSections-nSection));
		}
	}

	if(nSection != 0)
	{   // Zerofill last section header
		pSH = IMAGE_FIRST_SECTION(pNTH);
		memset(&pSH[pNTH->FileHeader.NumberOfSections], 0, sizeof(IMAGE_SECTION_HEADER));
	}

	return dwNewFsize;
}

void FixVSizes(IMAGE_NT_HEADERS * pNTH)
{
IMAGE_SECTION_HEADER * pSH;

	// fix virtual parts of the PE Header (a must for win2k)
	pSH = IMAGE_FIRST_SECTION(pNTH);
	for(WORD i=0; i < pNTH->FileHeader.NumberOfSections-1; i++)
	{
		pSH->Misc.VirtualSize = (pSH+1)->VirtualAddress - pSH->VirtualAddress;
		pSH++;
	}
	// (pSH -> pointer to last section)

	// align last section VSize to Sectionalignment
	pSH->Misc.VirtualSize = AlignUp(pSH->Misc.VirtualSize, HDR3264(pNTH, OptionalHeader.SectionAlignment));

	if(IsPE64(pNTH)){
		if(pSH->Misc.PhysicalAddress)
			((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->Misc.VirtualSize;
		else
			((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->SizeOfRawData;
	}
	else{
		if(pSH->Misc.PhysicalAddress)
			((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->Misc.VirtualSize;
		else
			((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->SizeOfRawData;
	}
}

DWORD AlignUp(DWORD dwBadSize, DWORD dwAlignment)
{
	dwAlignment--;
	return ((dwBadSize+dwAlignment) & ~dwAlignment);
}

DWORD AlignDown(DWORD dwBadSize, DWORD dwAlignment)
{
	dwAlignment--;
	return (dwBadSize & ~dwAlignment);
}
