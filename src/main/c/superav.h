/*
 * $Id$
 *
 * Copyright 2015 Valentyn Kolesnikov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#ifdef  _WIN32
    #ifndef FAR
        #define FAR
    #endif
    #ifndef NEAR
        #define NEAR
    #endif
#else
    #define FAR     far
    #define NEAR    near
#endif

typedef unsigned short word ;
typedef unsigned long dword ;
typedef unsigned char byte ;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef unsigned short WORD ;
typedef unsigned long DWORD ;
typedef unsigned char BYTE ;
typedef unsigned int UINT;
typedef unsigned long ULONG;

#define HEADER_SIZE 0x400
#define JUMP1_SIZE  0x400
#define EOF_SIZE    0x800
#define BUFFER_SIZE 0x4000
#define REDUN_SIZE  EOF_SIZE+0x200
#define ALL_SIZE    HEADER_SIZE+JUMP1_SIZE+EOF_SIZE+BUFFER_SIZE

#define HEADER_START    0
#define JUMP1_START     HEADER_SIZE
#define EOF_START       HEADER_SIZE+JUMP1_SIZE
#define BUFFER_START    HEADER_SIZE+JUMP1_SIZE+EOF_SIZE

#define OT_FILE         0x00
#define OT_SECTOR       0x01
#define OT_MEMORY       0x03

#define ST_COM  0x01
#define ST_EXE  0x02
#define ST_SYS  0x04
#define ST_NE   0x08
#define ST_JAVA 0x10

#define ST_MBR  0x01
#define ST_BOOT 0x02

#define ST_MCB      0x01
#define ST_CUT      0x02
#define ST_ADDRESS  0x03

#define R_CLEAN                 0
#define R_DETECT                1
#define R_PREDETECT             2
#define R_CURE                  3
#define R_PRECURE               4
#define R_DELETE                5
#define R_WARNING               6
#define R_FAIL                  7

typedef struct
{
    dword   Sector;
    dword   Checked;
    dword   Folder;
    dword   Infected;
    dword   Warnings;
    dword   Disinfected;
    dword   Deleted;
    dword   Error;
} COUNT;

typedef struct
{
    byte    header[HEADER_SIZE];
    byte    jump1[JUMP1_SIZE];
    byte    eof[EOF_SIZE];
    byte    buffer[BUFFER_SIZE];
    byte    redun[REDUN_SIZE];
    byte    Disk;
    word    Entry_Count;
    dword   File_Length;
    word    Redu_Length;
    byte    Object_Type;
    byte    Sub_Type;
    word    Exe_IP;
    dword   EP;
    dword   Tail;
    dword   RFlags;
    byte    flag_all_files;
    byte    flag_cure;
    byte    flag_ok;
    byte    flag_pages;
    byte    flag_subdir;
    byte    flag_list;
    byte    flag_boot;
    byte    flag_mem;
    byte    flag_delinf;
    byte    flag_rep;
    byte    flag_redun;
    byte    flag_stop_scan;
    byte    flag_notstop;
    int     OpenedFile;
    char    Fname[0x255];
    FILE    *ReportHandle;
    char    Repname[0x255];
    COUNT   Stat;
} BUFFER;

extern BUFFER LOCAL_DATA;
#define BU ((BUFFER*)&LOCAL_DATA)

#define Header  BU->header
#define Jump1   BU->jump1
#define Eof     BU->eof
#define Buffer  BU->buffer
#define Redun   BU->redun

typedef struct
{
    word    Magic;
    word    PartPag;
    word    PageCnt;
    word    ReloCnt;
    word    HdrSize;
    word    MinMem;
    word    MaxMem;
    word    SS;
    word    SP;
    word    ChkSum;
    word    IP;
    word    CS;
    word    TabOff;
    word    Overlay;
} HEADER_EXE;

#define HeaderExe ((HEADER_EXE*)Header)

typedef struct
{
    byte    sub_type;
    dword   check_dword;
    word    offset1;
    byte    len_crc1;
    dword   crc1;
    word    offset2;
    byte    len_crc2;
    dword   crc2;
    char*   virname;
    word    (*decode)(void);
    word    (*cure)(void);
} FILE_RECORD;

typedef struct
{
    dword   check_dword;
    word    offset1;
    byte    len_crc1;
    dword   crc1;
    word    offset2;
    byte    len_crc2;
    dword   crc2;
    char*   virname;
    word    (*decode)(void);
    word    (*cure)(void);
} SECTOR_RECORD;

typedef struct
{
    byte    sub_type;
    dword   check_dword;
    word    offset1;
    word    segment1;
    byte    len_crc1;
    dword   crc1;
    char*   virname;
    word    (*decode)(void);
    word    (*cure)(void);
    word    cure_off;
    byte    cure_data[6];
} MEM_RECORD;

typedef struct
{
    FILE_RECORD *file_r;
    word        file_records;
    MEM_RECORD  *mem_r;
    word        mem_records;
    SECTOR_RECORD  *sector_r;
    word        sector_records;
    word        total_records;
} AV_FILE;

extern AV_FILE GLOBAL_DATA, *AV_F;

#define     BH(offset)  (*(BYTE*)(Header+offset))
#define     WH(offset)  (*(WORD*)(Header+offset))
#define     DH(offset)  (*(DWORD*)(Header+offset))
#define     BA(offset)  (*(BYTE*)(Jump1+offset))
#define     WA(offset)  (*(WORD*)(Jump1+offset))
#define     DA(offset)  (*(DWORD*)(Jump1+offset))
#define     BC(offset)  (*(BYTE*)(Buffer+offset))
#define     WC(offset)  (*(WORD*)(Buffer+offset))
#define     DC(offset)  (*(DWORD*)(Buffer+offset))
#define     BE(offset)  (*(BYTE*)(Eof+offset))
#define     WE(offset)  (*(WORD*)(Eof+offset))
#define     DE(offset)  (*(DWORD*)(Eof+offset))

#ifdef _DEBUG
    #define DEBUG(x)    Printf x
#else
    #define DEBUG(x)
#endif

#define     SetFlag(flag)   {if (flag == (flags + 1)) flags |= flag; DEBUG(("Waiting for %03x", flags+1));}

extern int  Read(void *buf, uint count);
extern int  Write(void *buf, uint count);
extern long Seek(long Offset);
extern int  Seek_Read(long Offset,void *buf, uint count);
extern int  Seek_Write(long Offset,void *buf, uint count);
extern int  Ch_Size(long New_Size);
extern int  Read_13(word R_CX, byte R_DH, void *buf);
extern int  Write_13(word R_CX, byte R_DH, void *buf);
extern void Printf(char *fmt, ...);
extern void Copy_Data(void *dest, const void *src, uint n);
extern void Fill_Data(void *dest, byte b, uint n);
extern void Xor_Byte(byte *Source, byte *Dest, byte Key, word Len);
extern void Add_Byte(byte *Source, byte *Dest, byte Key, word Len);
extern void Xor_Word(byte *Source, byte *Dest, word Key, word Len);
extern void Add_Word(byte *Source, byte *Dest, word Key, word Len);
extern word CutPast_File(dword DstOff, dword SrcOff, dword Cut);
extern word Cure_COM_Imm(byte *Buf, word Len, long New_Size);
extern word Cure_EXE_Imm(byte *Exe_ip, byte *Exe_cs, byte *Exe_ss, byte *Exe_sp, long New_Size);
