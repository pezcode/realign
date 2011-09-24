/*

-> realign.dll by yoda

History:
~~~~~~~~
1.5:
- "ReBasePEImage" API added

1.4d:
- offset to section table is now calculated dynamically

1.4c:
- "ValidatePE" API added

1.4b:
- solved prob with binded files
- new realign mode: nice

1.4:
- WipeReloc API added

1.3a:
- bugs I caused while fixing the Watcom prob were fixed :)
- fixed a bug that let a lot of files don't work on NT after realigning them
  in the normal mode (the PE Signature can't be anywhere in the Header)

1.2:
- support for files being compiled with Watcom C/C++ added
- TruncateFile API added

1.11:
- SEH added
- Realign API returns error codes

1.1:
- hardcore realign mode added
- bugfixes

You are allowed to use this code if you mention my name.

*/

// thx ELiCZ for these nice linker commands
#pragma comment(linker,"/BASE:0x10000000 /FILEALIGN:512 /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")

#include <windows.h>
#include <imagehlp.h>
#include <stdlib.h>
#include "realign.h"

// functions
BOOL      __stdcall TruncateFile(CHAR* szFilePath,DWORD dwNewFsize);
DWORD               ValidAlignment(DWORD BadSize);
BOOL                IsRoundedTo(DWORD dwTarNum,DWORD dwRoundNum);
DWORD     __stdcall RealignPE(LPVOID AddressOfMapFile,DWORD dwFsize,BYTE bRealignMode);
DWORD     __stdcall WipeReloc(void* pMap, DWORD dwFsize);
BOOL      __stdcall ValidatePE(void* pPEImage, DWORD dwFileSize);
ReBaseErr __stdcall ReBasePEImage(void* pPE, DWORD dwNewBase);

// constants
#define MAX_SEC_NUM         30

const   DWORD ScanStartDS = 0x40;
const   MinSectionTerm    = 5;

// variables
DWORD                dwMapBase;
LPVOID               pMap;
DWORD				 dwTmpNum,dwSectionBase;
WORD                 wTmpNum;
CHAR *	             pCH;
WORD *			     pW;
DWORD *				 pDW;
LPVOID               pSections[MAX_SEC_NUM];
HMODULE              hDll;

PIMAGE_DOS_HEADER       pDosh;
PIMAGE_NT_HEADERS		pPeh;
PIMAGE_SECTION_HEADER   pSectionh;
int                     i,ii;
HANDLE					hFile,hMap;


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  fdwReason, 
                       LPVOID lpReserved
					 )
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		hDll = (HMODULE)hModule;
		DisableThreadLibraryCalls(hModule);
		break;
	}
    return TRUE;
}

BOOL __stdcall TruncateFile(CHAR* szFilePath,DWORD dwNewFsize)
{
	HANDLE hFile;

	hFile = CreateFile(szFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	SetFilePointer(hFile,dwNewFsize,NULL,FILE_BEGIN);
	SetEndOfFile(hFile);
	CloseHandle(hFile);
	return TRUE;
}

DWORD ValidAlignment(DWORD BadSize)
{
	div_t DivRes;

	DivRes = div(BadSize,0x200);
	if (DivRes.rem == 0)
		return BadSize;
	return ((DivRes.quot+1) * 0x200);
}

BOOL IsRoundedTo(DWORD dwTarNum,DWORD dwRoundNum)
{
	div_t  d;

	d = div(dwTarNum,dwRoundNum);
	return (d.rem == 0);
}

/*
Return values:
0 - access error while realigning
1 - at least one parameter is invalid
2 - invalid PE file
3 - too many sections - unsupported
4 - not enough memory
5 - resource not found
...else the file was realigned successfully and the new filesize is returned.
*/
DWORD __stdcall RealignPE(LPVOID AddressOfMapFile,DWORD dwFsize,BYTE bRealignMode)
{
	HRSRC    hRes;
	HGLOBAL  hgRes;
	void     *pStub;

	ZeroMemory(&pSections,sizeof(pSections));

	if (bRealignMode != REALIGN_MODE_NORMAL &&
		bRealignMode != REALIGN_MODE_HARDCORE &&
		bRealignMode != REALIGN_MODE_NICE) // is the RealignMode valid ?
		return 1;

	// get the other parameters
	pMap = AddressOfMapFile;
	dwMapBase = (DWORD)pMap;

	if (dwFsize == 0 || pMap == NULL)
		return 1;

	// access the PE Header and check whether it's a valid one
	pDosh = (PIMAGE_DOS_HEADER)(pMap);
	if (pDosh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 2;
	}
	pPeh = (PIMAGE_NT_HEADERS)((DWORD)pDosh+pDosh->e_lfanew);
	if (pPeh->Signature != IMAGE_NT_SIGNATURE)
	{
		return 2;
	}
	if (pPeh->FileHeader.NumberOfSections > MAX_SEC_NUM)
	{
		return 3;
	}

	__try
	{
		/* START */
		pPeh->OptionalHeader.FileAlignment = 0x200;

		/* Realign the PE Header */
		// get the size of all headers
		dwTmpNum = 0x18 + pPeh->FileHeader.SizeOfOptionalHeader +
			pPeh->FileHeader.NumberOfSections * 0x28;
		switch(bRealignMode)
		{
		case 0: // normal realign
			{
				// kill room between the "win32 pls" message and the PE signature
				// find the end of the message
				pW = (WORD*)(dwMapBase+ScanStartDS);
				while (*pW != 0 ||
					   (!IsRoundedTo((DWORD)pW,0x10)))
				{
					pW = (WORD*)((DWORD)pW+1);
				}
				wTmpNum = (WORD)((DWORD)pW-dwMapBase);
				if (wTmpNum < pDosh->e_lfanew)
				{
					CopyMemory((LPVOID)pW,(VOID*)pPeh,dwTmpNum); // copy the Header to the right place
					pDosh->e_lfanew = wTmpNum;
				}
				break;
			}
			break;
		case 1: // Hardcore Realign
			{
				// wipe the dos stub
				CopyMemory((LPVOID)(dwMapBase+0xC),(LPVOID)pPeh,dwTmpNum);
				pDosh->e_lfanew = 0xC;
			}
			break;
		case 2: // Nice Realign
			if (pDosh->e_lfanew > 40)
			{
				// get resource pointer
				hRes = FindResource(hDll, "NICE_STUB", "BINARYDATA");
				hgRes = LoadResource(hDll, hRes);
				pStub = LockResource(hgRes);
				if (!pStub)
					return 5;

				// paste stub
				memcpy(
					(void*)pDosh,
					pStub,
					0x40);
				// align NT header
				memcpy(
					(void*)((DWORD)pDosh + 0x40),
					(void*)pPeh,
					dwTmpNum);
			}
			break;
		}
		dwSectionBase = ValidAlignment(dwTmpNum + pDosh->e_lfanew);
		pPeh = (PIMAGE_NT_HEADERS)(dwMapBase+pDosh->e_lfanew); // because the NT header moved
		// correct the SizeOfHeaders
		pPeh->OptionalHeader.SizeOfHeaders = dwSectionBase;

		/* Realign all sections */
		// make a copy of all sections
		// this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
		pSectionh = (PIMAGE_SECTION_HEADER)(dwMapBase+pDosh->e_lfanew + 0x18 +\
			pPeh->FileHeader.SizeOfOptionalHeader);
		for (i=0; i<pPeh->FileHeader.NumberOfSections; i++)
		{
			if (pSectionh->SizeOfRawData == 0 || pSectionh->PointerToRawData == 0)
			{
				++pSectionh;
				continue;
			}
			// get a valid size
			dwTmpNum = pSectionh->SizeOfRawData;
			if ((pSectionh->SizeOfRawData+pSectionh->PointerToRawData) > dwFsize)
				dwTmpNum = dwFsize-pSectionh->PointerToRawData;
			dwTmpNum -= 1;
			// copy the section into some memory
			pSections[i] = GlobalAlloc(0,dwTmpNum);
			if (pSections[i] == NULL) // fatal error !!!
			{
				for (ii=0; ii<i-1; ii++)
					if (pSections[ii])
						GlobalFree(pSections[ii]);
				return 4;
			}
			CopyMemory(pSections[i],(LPVOID)(pSectionh->PointerToRawData+dwMapBase),dwTmpNum);
			++pSectionh;
		}

		// start realigning the sections
		pSectionh = (PIMAGE_SECTION_HEADER)(dwMapBase+pDosh->e_lfanew+ 0x18 +
			pPeh->FileHeader.SizeOfOptionalHeader);
		for (i=0;i<pPeh->FileHeader.NumberOfSections;i++)
		{
			// some anti crash code :P
			if (pSectionh->SizeOfRawData == 0 || pSectionh->PointerToRawData == 0)
			{
				++pSectionh;
				if (pSectionh->PointerToRawData == 0)
					continue;
				pSectionh->PointerToRawData = dwSectionBase;
				continue;
			}
			// let pCH point to the end of the current section
			if ((pSectionh->PointerToRawData+pSectionh->SizeOfRawData) <= dwFsize)
				pCH = (char*)(dwMapBase+pSectionh->PointerToRawData+pSectionh->SizeOfRawData-1);
			else
				pCH = (char*)(dwMapBase+dwFsize-1);
			// look for the end of this section
			while (*pCH == 0)
				--pCH;
			// calculate the new RawSize
			dwTmpNum = ((DWORD)pCH-dwMapBase)+MinSectionTerm-pSectionh->PointerToRawData;
			if (dwTmpNum < pSectionh->SizeOfRawData)
				pSectionh->SizeOfRawData = dwTmpNum;
			else // the new size is too BIG
				dwTmpNum = pSectionh->SizeOfRawData;
			// copy the section to the new place
			if (i != pPeh->FileHeader.NumberOfSections-1)
				dwTmpNum = 	ValidAlignment(dwTmpNum);
			CopyMemory((LPVOID)(dwMapBase+dwSectionBase),pSections[i],
				dwTmpNum);
			// set the RawOffset
			pSectionh->PointerToRawData = dwSectionBase;
			// get the RawOffset for the next section
			dwSectionBase = dwTmpNum+dwSectionBase; // the last section doesn't need to be aligned
			// go to the next section
			++pSectionh;
		}

		// delete bound import directories because it is destroyed if present
		pPeh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		pPeh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

		// clean up
		for (i=0;i<pPeh->FileHeader.NumberOfSections;i++)
			if (pSections[i])
				GlobalFree(pSections[i]);
	}
	__except(1)
	{
		// clean up
		for (i=0; i<pPeh->FileHeader.NumberOfSections; i++)
			if (pSections)
				GlobalFree(pSections[i]);
		return 0;
	}
	return dwSectionBase; // return the new filesize
}

// returns:
//  -1  - access violation
//  -2  - no relocation found
//  -3  - no own section
//  -4  - dll characteristics found
//  -5  - invalid PE file
//  else the new raw size
DWORD __stdcall WipeReloc(void* pMap, DWORD dwFsize)
{
	PIMAGE_DOS_HEADER       pDosH;
	PIMAGE_NT_HEADERS       pNTH;
	PIMAGE_SECTION_HEADER   pSecH;
	PIMAGE_SECTION_HEADER   pSH, pSH2;
	DWORD                   dwRelocRVA, i;
	BOOL                    bOwnSec           = FALSE;
	DWORD                   dwNewFsize;

	__try  // =)
	{
		// get pe header pointers
		pDosH = (PIMAGE_DOS_HEADER)pMap;
		if (pDosH->e_magic != IMAGE_DOS_SIGNATURE)
			return -5;
		pNTH  = (PIMAGE_NT_HEADERS)((DWORD)pDosH + pDosH->e_lfanew);
		if (pNTH->Signature != IMAGE_NT_SIGNATURE)
			return -5;
		pSecH = (PIMAGE_SECTION_HEADER)((DWORD)pNTH + 0x18 + pNTH->FileHeader.SizeOfOptionalHeader);

		// has PE dll characteristics ?
		if (pNTH->FileHeader.Characteristics & 0x2000)
			return -4;

		// is there a reloc section ?
		dwRelocRVA = pNTH->OptionalHeader.DataDirectory[5].VirtualAddress;
		if (!dwRelocRVA)
			return -2;

		// check whether the relocation has an own section
		pSH = pSecH;
		for (i=0; i < pNTH->FileHeader.NumberOfSections; i++)
		{
			if (pSH->VirtualAddress == dwRelocRVA)
			{
				bOwnSec = TRUE;
				break; // pSH -> reloc section header and i == section index
			}
			++pSH;
		}
		if (!bOwnSec)
			return -3;

		if (i+1 == pNTH->FileHeader.NumberOfSections)
		{
			//--- relocation is the last section ---
			// truncate at the start of the reloc section
			dwNewFsize = pSH->PointerToRawData;
		}
		else
		{
			//--- relocation isn't the last section ---
			dwNewFsize = dwFsize - pSH->SizeOfRawData;

			//-> copy the section(s) after the relocation to the start of the relocation
			pSH2 = pSH;
			++pSH2; // pSH2 -> pointer to first section after relocation
			memcpy(
				(void*)(pSH->PointerToRawData + (DWORD)pMap),
				(const void*)(pSH2->PointerToRawData + (DWORD)pMap),
				dwFsize - pSH2->PointerToRawData);

			//-> fix the section headers
			// (pSH -> reloc section header)
			// (pSH2 -> first section after reloc section)
			for (++i; i < pNTH->FileHeader.NumberOfSections; i++)
			{
				// apply important values
				pSH->SizeOfRawData    = pSH2->SizeOfRawData;
				pSH->VirtualAddress   = pSH2->VirtualAddress;
				pSH->Misc.VirtualSize = pSH2->Misc.VirtualSize;

				// apply section name
				memcpy(
					(void*)(pSH->Name),
					(const void*)(pSH2->Name),
					sizeof(pSH2->Name));
				++pSH;
				++pSH2;
			}
		}

		// dec section number
		--pNTH->FileHeader.NumberOfSections;

		// kill reloc directory entry
		pNTH->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
		pNTH->OptionalHeader.DataDirectory[5].Size           = 0;

		// fix virtual parts of the PE Header (a must for win2k)
		pSH2 = pSH = pSecH;
		++pSH2;
		for (i=0; i < (DWORD)pNTH->FileHeader.NumberOfSections-1; i++)
		{
			pSH->Misc.VirtualSize = pSH2->VirtualAddress - pSH->VirtualAddress;
			++pSH;
			++pSH2;
		}
		// (pSH -> pointer to last section)
		if (pSH->Misc.PhysicalAddress)
			pNTH->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->Misc.VirtualSize;
		else // WATCOM is always a bit special >:-)
			pNTH->OptionalHeader.SizeOfImage = pSH->VirtualAddress + pSH->SizeOfRawData;
	}
	__except(1)
	{
		// an access violation occurred :(
		return -1;
	}

	return dwNewFsize;
}

BOOL __stdcall ValidatePE(void* pPEImage, DWORD dwFileSize)
{
	PIMAGE_NT_HEADERS       pNTh;
	PIMAGE_SECTION_HEADER   pSech,pSH, pSH2, pLastSH;
	UINT                    i;
	DWORD                   dwHeaderSize;

	// get PE base information
	pNTh = ImageNtHeader(pPEImage);
	if (!pNTh)
		return FALSE;
	pSech = (PIMAGE_SECTION_HEADER)((DWORD)pNTh + + 0x18 + pNTh->FileHeader.SizeOfOptionalHeader);

	// FIX:
	// ... the SizeOfHeaders
	pSH = pSech;
	dwHeaderSize = 0xFFFFFFFF;
	for(i=0; i < pNTh->FileHeader.NumberOfSections; i++)
	{
		if (pSH->PointerToRawData && pSH->PointerToRawData < dwHeaderSize)
			dwHeaderSize = pSH->PointerToRawData;
		++pSH;
	}
	pNTh->OptionalHeader.SizeOfHeaders = dwHeaderSize;

	// ...Virtual Sizes
	pSH2 = pSH = pSech;
	++pSH2;
	for (i=0; i < (DWORD)pNTh->FileHeader.NumberOfSections-1; i++)
	{
		pSH->Misc.VirtualSize = pSH2->VirtualAddress - pSH->VirtualAddress;
		++pSH;
		++pSH2;
	}

	// (pSH -> pointer to last section)
	pLastSH = pSH;

	// ...RawSize of the last section
	pLastSH->SizeOfRawData = dwFileSize - pLastSH->PointerToRawData;

	// ...SizeOfImage
	if (pLastSH->Misc.PhysicalAddress)
		pNTh->OptionalHeader.SizeOfImage = pLastSH->VirtualAddress + pLastSH->Misc.VirtualSize;
	else // WATCOM is always a bit special >:-)
		pNTh->OptionalHeader.SizeOfImage = pLastSH->VirtualAddress + pLastSH->SizeOfRawData;

	return TRUE;
}

ReBaseErr __stdcall ReBasePEImage(void* pPE, DWORD dwNewBase)
{
	PIMAGE_NT_HEADERS    pNT;
	PIMAGE_RELOCATION    pR;
	ReBaseErr            ret;
	DWORD                dwDelta, *pdwAddr, dwRva, dwType;
	UINT                 iItems, i;
	WORD                 *pW;

	// dwNewBase valid ?
	if (dwNewBase & 0xFFFF)
	{
		ret = RB_INVALIDNEWBASE;
		goto Exit; // ERR
	}

	//
	// get relocation dir ptr
	//
	pNT = ImageNtHeader(pPE);
	if (!pNT)
	{
		ret = RB_INVALIDPE;
		goto Exit; // ERR
	}
	// new base = old base ?
	if (pNT->OptionalHeader.ImageBase == dwNewBase)
	{
		ret = RB_OK;
		goto Exit; // OK
	}
	if (!pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		ret = RB_NORELOCATIONINFO;
		goto Exit; // ERR
	}
	pR = (PIMAGE_RELOCATION)ImageRvaToVa(
		pNT,
		pPE,
		pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
		NULL);
	if (!pR)
	{
		ret = RB_INVALIDRVA;
		goto Exit; // ERR
	}

	//
	// add delta to relocation items
	//
	dwDelta = dwNewBase - pNT->OptionalHeader.ImageBase;
	__try
	{
		do
		{
			// get number of items
			if (pR->SymbolTableIndex)
				iItems = (pR->SymbolTableIndex - 8) / 2;
			else
				break; // no items in this block

			// trace/list block items...
			pW = (WORD*)((DWORD)pR + 8);
			for (i = 0; i < iItems; i++)
			{
				dwRva  = (*pW & 0xFFF) + pR->VirtualAddress;
				dwType = *pW >> 12;
				if (dwType != 0) // fully compatible ???
				{
					// add delta
					pdwAddr = (PDWORD)ImageRvaToVa(
						pNT,
						pPE,
						dwRva,
						NULL);
					if (!pdwAddr)
					{
						ret = RB_INVALIDRVA;
						goto Exit; // ERR
					}
					*pdwAddr += dwDelta;
				}
				// next item
				++pW;
			}

			pR = (PIMAGE_RELOCATION)pW; // pR -> next block header
		} while ( *(DWORD*)pW );
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ret = RB_ACCESSVIOLATION;
		goto Exit; // ERR
	}

	// apply new base to header
	pNT->OptionalHeader.ImageBase = dwNewBase;

	ret = RB_OK; // OK

Exit:
	return ret;
}