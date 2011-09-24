
/*****************************************************************************

  Realign.h
  ---------

  for version: 1.6

  Include file for Realign.dll.

  by yoda

*****************************************************************************/

#ifndef __Realign_h__
#define __Realign_h__

// Macro to check the success of RealignPE[Ex] and WipeData [WipeReloc]
#define REALIGNDLLAPI_SUCCESS(RetValue) ((signed long)RetValue > 4)
//#define REALIGNDLLAPI_SUCCESS(RetValue) (RetValue < 0xF0000000 && RetValue > 30)

enum RealignMode : BYTE
{
REALIGN_MODE_NORMAL   = 0,
REALIGN_MODE_HARDCORE = 1,
REALIGN_MODE_NICE     = 2
};

enum RealignError : signed long
{
// RealignPE[Ex]
RA_ACCESSVIOLATION = 0,
RA_INVALIDPARAM    = 1,
RA_INVALIDPE       = 2,
RA_TOOMANYSECTIONS = 3,
RA_OUTOFMEMORY     = 4,
//ReBasePEImage[Ex]
RB_OK               = 0,
RB_INVALIDPE        = 1,
RB_NORELOCATIONINFO = 2,
RB_INVALIDRVA       = 3,
RB_INVALIDNEWBASE   = 4,
RB_ACCESSVIOLATION  = 5,
// WipeData
WD_ACCESSVIOLATION = -1,
WD_NODATA          = -2,
WD_NOOWNSECTION    = -3,
WD_INVALIDPE       = -4,
WD_INVALIDDATA     = -5,
// WipeReloc
WR_ACCESSVIOLATION = -1,
WR_NODATA          = -2,
WR_NOOWNSECTION    = -3,
WR_NODLL           = -4,
WR_INVALIDPE       = -5,
// RebuildResDir
RR_INVALIDPE   = 0,
RR_NORESDIR    = 1,
RR_INVALIDDATA = 2
};

/*
// RealignPE[Ex] realign modes
#define REALIGN_MODE_NORMAL   0
#define REALIGN_MODE_HARDCORE 1
#define REALIGN_MODE_NICE     2

// RealignPE[Ex] return values
#define RA_ACCESSVIOLATION    0
#define RA_INVALIDPARAM       1
#define RA_INVALIDPE          2
#define RA_TOOMANYSECTIONS    3
#define RA_OUTOFMEMORY        4
// ReBasePEImage[Ex] return values
#define RB_OK                 0
#define RB_INVALIDPE          1
#define RB_NORELOCATIONINFO   2
#define RB_INVALIDRVA         3
#define RB_INVALIDNEWBASE     4
#define RB_ACCESSVIOLATION    5
// WipeData return values
#define WD_ACCESSVIOLATION   -1
#define WD_NODATA            -2
#define WD_NOOWNSECTION      -3
#define WD_INVALIDPE         -4
#define WD_INVALIDDATA       -5
// WipeReloc return values
#define WR_ACCESSVIOLATION   -1
#define WR_NODATA            -2
#define WR_NOOWNSECTION      -3
#define WR_NODLL             -4
#define WR_INVALIDPE         -5
// RebuildResDir return values
#define RR_INVALIDPE          0
#define RR_NORESDIR           1
#define RR_INVALIDDATA        2
*/

#ifndef __cplusplus
	typedef unsigned char bool;
	const bool true  = 1;
	const bool false = 0;
#endif

// function prototypes
#ifdef __cplusplus
extern "C"
{
#endif

void * __stdcall MapFile(const char * szFilePath, DWORD * pdwFsize);
bool   __stdcall UnmapFile(const char * szFilePath, void * pMap, DWORD dwFsize);
bool   __stdcall TruncateFile(const char * szFilePath, DWORD dwNewFsize);
DWORD  __stdcall RealignPE(void * pMap, DWORD dwFsize, BYTE bRealignMode);
DWORD  __stdcall RealignPEEx(void * pMap, DWORD dwFsize, BYTE bRealignMode, WORD wNewAlign, bool blAlignRawsizes, bool blStripEmptySections);
DWORD  __stdcall ReBasePEImage(void * pMap, DWORD dwNewBase);
DWORD  __stdcall ReBasePEImageEx(void * pMap, DWORD dwFsize, ULONGLONG ulNewBase);
DWORD  __stdcall WipeData(void * pMap, DWORD dwFsize, BYTE bData, bool blZerofill);
DWORD  __stdcall WipeReloc(void * pMap, DWORD dwFsize);
bool   __stdcall FixChecksum(void * pMap, DWORD dwFsize);
bool   __stdcall ValidatePE(void * pMap, DWORD dwFsize);

#ifdef __cplusplus
}
#endif

#endif // __Realign_h__
