/*
   realign.dll (1.5] by yoda
   modifications [1.6) by pezcode

   You are allowed to use this code if you mention my name. (yoda's that is)
*/

#include <windows.h>
#include <cstdlib> // _countof
#include <new>
#include "realign.h"
#include "functions.h"

// constants
const size_t MAX_SEC_NUM = 96; // max number of sections supported by the Windows loader

// global variables
HMODULE hDll;

IMAGE_DOS_HEADER NiceStub =
{
	IMAGE_DOS_SIGNATURE, // e_magic
	0x0090, // e_cblp
	0x0003, // e_cp
	0x0000, // e_crlc
	0x0004, // e_cparhdr
	0x0000, // e_minalloc
	0xFFFF, // e_maxalloc
	0x0000, // e_ss
	0x00B8, // e_sp
	0x0000, // e_csum
	0x0000, // e_ip
	0x0000, // e_cs
	0x0040, // e_lfarlc
	0x0000, // e_ovno
	{0},    // e_res[4]
	0x0000, // e_oemid
	0x0000, // e_oeminfo
	{0},    // e_res2[10]
	sizeof(IMAGE_DOS_HEADER) // e_lfanew
};

// ----------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return TRUE;
}

// ----------

void * __stdcall MapFile(const char * szFilePath, DWORD * pdwFsize)
{
HANDLE hFile;
DWORD dwFsize, dwFsizeHigh;
const DWORD MaxFsize = 1 * 1024 * 1024 * 1024; // GB * MB * KB * B
void * pMap = 0;
DWORD  dwBytes;

	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		dwFsize = GetFileSize(hFile, &dwFsizeHigh);
		if(!dwFsizeHigh && dwFsize <= MaxFsize) // Files > 1GB not supported
		{
			if(pdwFsize) *pdwFsize = dwFsize;
			pMap = VirtualAlloc(0, dwFsize, MEM_COMMIT, PAGE_READWRITE);
			if(pMap)
			{
				if(!ReadFile(hFile, pMap, dwFsize, &dwBytes, 0))
				{
					VirtualFree(pMap, 0, MEM_RELEASE);
					pMap = 0;
				}
			}
		}
		CloseHandle(hFile);
	}
	return pMap;
}

bool __stdcall UnmapFile(const char * szFilePath, void * pMap, DWORD dwFsize)
{
HANDLE hFile;
DWORD dwBytes;
bool RetVal = false;

	hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		RetVal = WriteFile(hFile, pMap, dwFsize, &dwBytes, 0) ? true : false;
		SetEndOfFile(hFile);
		CloseHandle(hFile);
		VirtualFree(pMap, 0, MEM_RELEASE);
	}
	return RetVal;
}

bool __stdcall TruncateFile(const char * szFilePath, DWORD dwNewFsize)
{
HANDLE hFile;

	hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile, dwNewFsize, NULL, FILE_BEGIN);
		SetEndOfFile(hFile);
		CloseHandle(hFile);
		return true;
	}
	return false;
}

/*
Return values:
0 - access error while realigning
1 - at least one parameter is invalid
2 - invalid PE file
3 - too many sections - unsupported
4 - not enough memory
...else the new filesize
*/

DWORD __stdcall RealignPE(void * pMap, DWORD dwFsize, BYTE bRealignMode)
{
	return RealignPEEx(pMap, dwFsize, bRealignMode, 0x200, false, false);
}

DWORD __stdcall RealignPEEx(void * pMap, DWORD dwFsize, BYTE bRealignMode, WORD wNewAlign, bool blAlignRawSizes, bool blStripEmptySections)
{
IMAGE_DOS_HEADER * pDosH;
IMAGE_NT_HEADERS * pNTH;
IMAGE_SECTION_HEADER * pSH;
BYTE * pSections[MAX_SEC_NUM] = { 0 };
BYTE * bptrMapBase;
DWORD dwSectionBase, dwHdrSize, dwNewSize;
//WORD wNPEHStart;
//WORD * pW;
BYTE * SecOffset, * pCH;

	// TODO asserts

	if(pMap == 0 || dwFsize == 0)
		return RA_INVALIDPARAM;

	if(!ValidFileAlignment(wNewAlign))
		return RA_INVALIDPARAM;

	if(!GetNTHeader(pMap, dwFsize, &pDosH, &pNTH, 0, 0))
		return RA_INVALIDPE;

	if(wNewAlign > pNTH->OptionalHeader.SectionAlignment)
		return RA_INVALIDPARAM;

	if(pNTH->FileHeader.NumberOfSections > MAX_SEC_NUM)
		return RA_TOOMANYSECTIONS;

	bptrMapBase = (BYTE *)pMap;

	/* Realign the PE Header */

	dwHdrSize = SizeOfPEHeader(pNTH);

	switch(bRealignMode)
	{
		/*
		case REALIGN_MODE_NORMAL:
			
			// kill room between the "win32 pls" message and the PE signature
			// find the end of the message
			pW = (WORD *)(bptrMapBase+sizeof(IMAGE_DOS_HEADER));
			while((*pW != 0 || ((ULONG_PTR)pW % 0x10)) && ((ULONG_PTR)pW < (ULONG_PTR)pNTH))
				(BYTE *)pW++;
			wNPEHStart = (WORD)((BYTE*)pW-bptrMapBase);
			if(wNPEHStart < pDosH->e_lfanew)
			{
				memcpy(pW, pNTH, dwHdrSize); // copy the Header to the right place
				pDosH->e_lfanew = wNPEHStart;
			}
			break;
		*/
		case REALIGN_MODE_HARDCORE: // completely wipe the dos stub
			memcpy(bptrMapBase+0xC, pNTH, dwHdrSize);
			pDosH->e_lfanew = 0xC; // overwrites BaseOfData
			break;
		case REALIGN_MODE_NORMAL:
		case REALIGN_MODE_NICE: // paste new stub, append PE header
			if(pDosH->e_lfanew > sizeof(NiceStub))
			{
				*pDosH = NiceStub;
				memcpy(bptrMapBase + sizeof(IMAGE_DOS_HEADER), pNTH, dwHdrSize);
			}
			break;
		default:
			return RA_INVALIDPARAM;
	}

	// Size of all headers
	dwHdrSize += pDosH->e_lfanew;
	dwSectionBase = AlignUp(dwHdrSize, wNewAlign);
	// get new PE header offset
	pNTH = (IMAGE_NT_HEADERS *)(bptrMapBase+pDosH->e_lfanew);
	pNTH->OptionalHeader.SizeOfHeaders = dwSectionBase;

	/* Realign all sections */

	// make a copy of all sections
	// this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)

	pSH = IMAGE_FIRST_SECTION(pNTH);

	for(int i = 0; i < pNTH->FileHeader.NumberOfSections; i++)
	{
		if(pSH[i].PointerToRawData == 0)
		{
			pSH[i].SizeOfRawData = 0; // Don't copy them, no memory allocated!
		}
		else if(pSH[i].SizeOfRawData != 0)
		{
			// get a valid RawOffset
			pSH[i].PointerToRawData = AlignDown(pSH[i].PointerToRawData, FILEALIGNMENT_DOWN);
			// ???

			// get the smallest size
			if(pSH[i].Misc.VirtualSize < pSH[i].SizeOfRawData)
				pSH[i].SizeOfRawData = pSH[i].Misc.VirtualSize;

			// If size exceeds filesize, get bytes till end of file
			if((pSH[i].PointerToRawData + pSH[i].SizeOfRawData) > dwFsize)
				pSH[i].SizeOfRawData = dwFsize - pSH[i].PointerToRawData;

			// get size without trailing zeroes
			SecOffset = bptrMapBase + pSH[i].PointerToRawData;
			pCH = SecOffset + pSH[i].SizeOfRawData - 1;
			while((pCH >= SecOffset) && *pCH == 0)
				pCH--;
			pSH[i].SizeOfRawData = (DWORD)(pCH - SecOffset + 1);

			if(pSH[i].SizeOfRawData != 0)
			{
				try
				{
					pSections[i] = new BYTE[pSH[i].SizeOfRawData];
				}
				catch(std::bad_alloc&)
				{
					for(int j = 0; j < i; j++)
					{
						delete[] pSections[j];
					}
					return RA_OUTOFMEMORY;
				}

				memcpy(pSections[i], bptrMapBase+pSH[i].PointerToRawData, pSH[i].SizeOfRawData);
			}
		}
	}

	// Zerofill executable to remove junk
	memset(bptrMapBase+dwHdrSize, 0, dwFsize-dwHdrSize);

	// copy sections
	for(int i = 0; i < pNTH->FileHeader.NumberOfSections; i++)
	{
		// set new RawOffset
		pSH[i].PointerToRawData = dwSectionBase;

		// don't copy empty sections (pSections[i] == NULL)
		if(pSH[i].SizeOfRawData != 0)
		{
			// copy section to the new place
			memcpy(bptrMapBase+dwSectionBase, pSections[i], pSH[i].SizeOfRawData);

			// get aligned size for new RawOffset (not needed for the last section -> return correct file size)
			if(blAlignRawSizes || i+1 != pNTH->FileHeader.NumberOfSections)
				dwNewSize = AlignUp(pSH[i].SizeOfRawData, wNewAlign);

			// get aligned RawSize
			if(blAlignRawSizes)
				pSH[i].SizeOfRawData = dwNewSize;

			// get RawOffset for the next section
			dwSectionBase += dwNewSize;
		}
	}

	// Strip sections with a rawsize of 0
	if(blStripEmptySections)
	{
		for(int i = 0; i < pNTH->FileHeader.NumberOfSections; i++)
		{
			if(pSH[i].SizeOfRawData == 0)
				StripSection(pMap, dwFsize, i);
		}
	}

	pNTH->OptionalHeader.FileAlignment = wNewAlign;

	// delete bound import directories (destroyed if present)
	if(IsPE64(pNTH))
	{
		((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size =           0;
	}
	else
	{
		((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size =           0;
	}

	// clean up
	for(int i = 0; i < _countof(pSections); i++)
	{
		delete[] pSections[i];
	}

	return dwSectionBase; // return the new filesize
}

DWORD __stdcall ReBasePEImage(void * pMap, DWORD dwNewBase)
{
	return ReBasePEImageEx(pMap, ~0, dwNewBase);
}

DWORD __stdcall ReBasePEImageEx(void * pMap, DWORD dwFsize, ULONGLONG ulNewBase)
{
IMAGE_NT_HEADERS * pNTH;
IMAGE_RELOCATION * pR;
DWORD dwRelDir, dwRva, Type;
ULONGLONG ulOldBase, ulDelta;
ULONGLONG * pAddr;
WORD * pW;
int nItems;

	if(!GetNTHeader(pMap, dwFsize, 0, &pNTH, 0, 0))
		return RB_INVALIDPE;

	if(ulNewBase & 0xFFFF)
		return RB_INVALIDNEWBASE;

	ulOldBase = HDR3264(pNTH, OptionalHeader.ImageBase);

	if(ulOldBase == ulNewBase)
		return RB_OK;

	dwRelDir = HDR3264(pNTH, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if(!dwRelDir)
		return RB_NORELOCATIONINFO;

	// get relocation dir ptr
	pR = (IMAGE_RELOCATION *)((ULONG_PTR)pMap + RVAToOffset(dwRelDir, pMap));
	if((void *)pR == pMap)
		return RB_INVALIDRVA;

	/* add delta to relocation items */

	ulDelta = ulNewBase - ulOldBase;

	__try
	{
		while(pR->VirtualAddress)
		{
			/*
			if(!pR->SymbolTableIndex)
				break; // no items in this block
			*/

			// calculate number of items
			nItems = (pR->SymbolTableIndex - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(pR->Type);

			// walk block items
			pW = &pR->Type;
			for(int i = 0; i < nItems; i++)
			{
				dwRva = (pW[i] & 0xFFF) + pR->VirtualAddress; // get item RVA
				Type  = pW[i] >> 12;                          // get relocation type

				pAddr = (ULONGLONG *)((ULONG_PTR)pMap + RVAToOffset(dwRva, pMap));
				if((void *)pAddr == pMap)
					return RB_INVALIDRVA;

				// add delta value
				switch(Type)
				{
					case IMAGE_REL_BASED_HIGHLOW:
					case IMAGE_REL_BASED_DIR64:
						*pAddr += ulDelta;
						break;
				}
			}

			// get next block header
			pR = (IMAGE_RELOCATION *)((ULONG_PTR)pR + pR->SymbolTableIndex); 
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return RB_ACCESSVIOLATION;
	}

	// write new base to header
	if(IsPE64(pNTH))
		((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.ImageBase = ulNewBase;
	else
		((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.ImageBase = (DWORD)(ulNewBase & 0xFFFFFFFF);

	return RB_OK;
}

/*
Param bData:

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
*/

/*
Return values:
-1 - access violation
-2 - no data directory found
-3 - no own section
-4 - invalid PE file
...else the new raw size
*/

DWORD __stdcall WipeData(void * pMap, DWORD dwFsize, BYTE bData, bool blZerofill)
{
IMAGE_NT_HEADERS * pNTH;
IMAGE_SECTION_HEADER * pSH;
DWORD dwDataRVA, dwDataOffset, dwDataSize;
DWORD dwNewFsize;
bool bOwnSec = false;
unsigned int i;

	__try  // =)
	{
		if(!GetNTHeader(pMap, dwFsize, 0, &pNTH, &pSH, 0))
			return WD_INVALIDPE;

		// is there a data section ?
		if(bData >= HDR3264(pNTH, OptionalHeader.NumberOfRvaAndSizes))
			return WD_NODATA;
		dwDataRVA = HDR3264(pNTH, OptionalHeader.DataDirectory[bData].VirtualAddress);
		if(!dwDataRVA)
			return WD_NODATA;

		if(blZerofill)
		{
			dwDataOffset = RVAToOffset(dwDataRVA, pMap);
			dwDataSize   = HDR3264(pNTH, OptionalHeader.DataDirectory[bData].Size);

			if(!dwDataOffset || ((dwDataOffset+dwDataSize) > dwFsize))
				return WD_INVALIDDATA;

			memset((void *)((ULONG_PTR)pMap + dwDataOffset), 0, dwDataSize);
		}

		// check whether the directory has an own section
		for(i = 0; i < pNTH->FileHeader.NumberOfSections; i++)
		{
			if(pSH[i].VirtualAddress == dwDataRVA)
			{
				bOwnSec = true; // i == data section index
				break;
			}
		}

		if(!bOwnSec && !blZerofill)
			return WD_NOOWNSECTION;

		//if(blZerofill || bOwnSec)
		{
			// kill data directory entry
			if(IsPE64(pNTH)){
				((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.DataDirectory[bData].VirtualAddress = 0;
				((IMAGE_NT_HEADERS64 *)pNTH)->OptionalHeader.DataDirectory[bData].Size           = 0;
			}
			else{
				((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.DataDirectory[bData].VirtualAddress = 0;
				((IMAGE_NT_HEADERS32 *)pNTH)->OptionalHeader.DataDirectory[bData].Size           = 0;
			}
		}
		//else if(!bOwnSec)
		//	return WD_NOOWNSECTION;

		if(bOwnSec)
		// delete section
		dwNewFsize = StripSection(pMap, dwFsize, i);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// an access violation occurred :(
		return WD_ACCESSVIOLATION;
	}

	return dwNewFsize;
}

/*
Return values:
-1 - access violation
-2 - no relocation found
-3 - no own section
-4 - dll characteristics found
-5 - invalid PE file
...else the new raw size
*/

DWORD __stdcall WipeReloc(void * pMap, DWORD dwFsize)
{
IMAGE_NT_HEADERS * pNTH;
DWORD RetVal;

	if(!GetNTHeader(pMap, dwFsize, 0, &pNTH, 0, 0))
		return WR_INVALIDPE;

	// does the PE have dll characteristics ?
	if(pNTH->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return WR_NODLL;

	RetVal = WipeData(pMap, dwFsize, IMAGE_DIRECTORY_ENTRY_BASERELOC, false);
	if(REALIGNDLLAPI_SUCCESS(RetVal))
		pNTH->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	return RetVal;
}

// Code taken from WineHQ
bool __stdcall FixChecksum(void * pMap, DWORD dwFsize)
{
IMAGE_NT_HEADERS * pNTH;
DWORD dwCalcSum = 0;
WORD * pW;
unsigned int nWordCount;

	if(!GetNTHeader(pMap, dwFsize, NULL, &pNTH, NULL, NULL))
		return false;

	// don't include the old checksum in the new one
	pNTH->OptionalHeader.CheckSum = 0;

	nWordCount = (dwFsize+1)/sizeof(WORD);

	pW = (WORD *)pMap;
	for(unsigned int i = 0; i < nWordCount; i++)
	{
		dwCalcSum += *pW++;
		if(HIWORD(dwCalcSum) != 0)
			dwCalcSum = LOWORD(dwCalcSum) + HIWORD(dwCalcSum);
	}
	dwCalcSum = (WORD)(LOWORD(dwCalcSum) + HIWORD(dwCalcSum));

	// add file length
	dwCalcSum += dwFsize;

	pNTH->OptionalHeader.CheckSum = dwCalcSum;

	return true;
}

bool __stdcall ValidatePE(void * pMap, DWORD dwFsize)
{
IMAGE_NT_HEADERS * pNTH;
IMAGE_SECTION_HEADER * pSH;
DWORD TempVal;

	if(!GetNTHeader(pMap, dwFsize, NULL, &pNTH, &pSH, NULL))
		return false;

	pNTH->OptionalHeader.SizeOfHeaders = AlignUp((SizeOfPEHeader(pNTH) + ((IMAGE_DOS_HEADER *)pMap)->e_lfanew), pNTH->OptionalHeader.FileAlignment);

	// align rawoffsets and sizes
	for(int i = 0; i < pNTH->FileHeader.NumberOfSections; i++)
	{
		TempVal = AlignDown(pSH[i].PointerToRawData, FILEALIGNMENT_DOWN);
		if(TempVal != 0) // make sure we don't round down to 0
			pSH[i].PointerToRawData = TempVal;
		if(pSH[i].PointerToRawData >= dwFsize) // invalid raw offset
			pSH[i].PointerToRawData = pSH[i].SizeOfRawData = 0;
		// adjust raw size
		pSH[i].SizeOfRawData = AlignUp(pSH[i].SizeOfRawData, pNTH->OptionalHeader.FileAlignment);
		if((TempVal + pSH[i].SizeOfRawData) > dwFsize)
			pSH[i].SizeOfRawData = dwFsize - TempVal;
	}

	// fix section VSizes and SizeOfImage
	FixVSizes(pNTH);

	return true;
}

/*
DWORD RebuildResDir(void * pMap, DWORD dwFsize)
{
IMAGE_NT_HEADERS * pNTH;
IMAGE_RESOURCE_DIRECTORY * pResDir;
DWORD dwResRVA;

	if(!GetNTHeader(pMap, dwFsize, NULL, &pNTH, NULL, NULL))
		return RR_INVALIDPE;

	dwResRVA = HDR3264(pNTH, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	if(!dwResRVA)
		return RR_NORESDIR;

	pResDir = (IMAGE_RESOURCE_DIRECTORY *)((ULONG_PTR)pMap + RVAToOffset(dwResRVA, pMap));
	if((void *)pResDir == pMap)
		return RR_INVALIDDATA;
}
*/
