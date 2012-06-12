/* Silly ANTIVIRUS Version 1.0 build 021                        */
/* Written by Valentin Kolesnikov, e-mail: javadev75@gmail.com  */

#include <stdio.h>
#include <io.h>
#include <dos.h>
#include <stdarg.h>
#include <conio.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <fcntl.h>
#include <sys\stat.h>
#include <string.h>
#include "sillyav.h"

BUFFER LOCAL_DATA;//, *BU = &LOCAL_DATA;

void scan_path(char *CurrDir);

void Printf(char *fmt, ...)
{
    va_list argptr;

    va_start(argptr, fmt);
    if (BU->flag_rep)
    {
        vfprintf(BU->ReportHandle, fmt, argptr);
        fprintf(BU->ReportHandle,"\n");
    }
    vprintf(fmt, argptr);
    va_end(argptr);
    printf("\n");
}

void Rprintf(char *fmt, ...)
{
    va_list argptr;

    va_start(argptr, fmt);
    if (BU->flag_rep)
    {
        vfprintf(BU->ReportHandle, fmt, argptr);
    }
    vprintf(fmt, argptr);
    va_end(argptr);
}

void Roprintf(char *fmt, ...)
{
    va_list argptr;

    va_start(argptr, fmt);
    if (BU->flag_rep)
    {
        vfprintf(BU->ReportHandle, fmt, argptr);
    }
    va_end(argptr);
}

/**
Category: DOS kernel
INT 21 - Windows95 - LONG FILENAME - CREATE OR OPEN FILE

    AX = 716Ch
    BX = access mode and sharing flags (see #01782,also AX=6C00h)
    CX = attributes
    DX = action (see #01781)
    DS:SI -> ASCIZ filename
    DI = alias hint (number to append to short filename for disambiguation)
Return: CF clear if successful
        AX = file handle
        CX = action taken
        0001h file opened
        0002h file created
        0003h file replaced
    CF set on error
        AX = error code (see #01680)
        7100h if function not supported
SeeAlso: AX=6C00h,AX=7141h,AX=7156h,AX=71A9h
*/

int openFile(void *filename, word mode)
{
#ifndef _WIN32
    struct  REGPACK regpack;
    byte    count_try;

    count_try = 1;
    regpack.r_flags |= 1;
    while (count_try && (regpack.r_flags&1) )
    {
        count_try--;
        regpack.r_ax = 0x716C;
        regpack.r_bx = 0x0;
        regpack.r_cx = 0x2F;
        regpack.r_dx = 0x1;
        regpack.r_si = FP_OFF(filename);
        regpack.r_ds = FP_SEG(filename);
        intr(0x21, &regpack);
    }
    return regpack.r_flags&1 ? -1 : regpack.r_ax;
#else
    return _open(filename, mode);
#endif
}

int Read(void *buf, uint count)
{
    return _read(BU->OpenedFile,buf,count);
}

int Write(void *buf, uint count)
{
    return _write(BU->OpenedFile,buf,count);
}

long Seek(long Offset)
{
    return lseek(BU->OpenedFile,Offset,SEEK_SET);
}

int Seek_Read(long Offset,void *buf, uint count)
{
    lseek(BU->OpenedFile,Offset,SEEK_SET);
    return _read(BU->OpenedFile,buf,count);
}

int Seek_Write(long Offset,void *buf, uint count)
{
    lseek(BU->OpenedFile,Offset,SEEK_SET);
    return _write(BU->OpenedFile,buf,count);
}

word Fill_File(long Offset, byte Byte, word Len)
{
    if (Len <= BUFFER_SIZE)
    {
        memset(Buffer,Byte,Len);
        if (Seek_Write(Offset,Buffer,Len) == Len)
            return R_CURE;
    }
    return R_FAIL;
}

int Ch_Size(long New_Size)
{
    Fill_File(New_Size,0,(word)(BU->File_Length-New_Size));
    if (New_Size == 0)
    {
        return R_DELETE;
    }
    chsize(BU->OpenedFile,New_Size);
    BU->File_Length = New_Size;
    Seek(0L);
    return R_CURE;
}

dword CRCTab[256];

void InitCRC(void)
{
    int I, J;
    dword C;

    for (I=0;I<256;I++)
    {
        for (C=I,J=0;J<8;J++)
            C=(C & 1) ? (C>>1)^0xEDB88320L : (C>>1);
        CRCTab[I]=C;
    }
}

dword calc_crc(byte FAR*Addr,uint Size)
{
    uint I;
    dword StartCRC = 0xFFFFFFFFl;

    for (I=0; I<Size; I++)
        StartCRC = CRCTab[(byte)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
    return(StartCRC);
}

void Xor_Byte(byte *Source, byte *Dest, byte Key, word Len)
{
    int i;
    for (i=0;i<Len;i++)
    {
        Dest[i] = Source[i] ^ Key;
    }
}

void Add_Byte(byte *Source, byte *Dest, byte Key, word Len)
{
    int i;
    for (i=0;i<Len;i++)
    {
        Dest[i] = Source[i] + Key;
    }
}

void Xor_Word(byte *Source, byte *Dest, word Key, word Len)
{
    int i;
    for (i=0;i<Len;i+=2)
    {
        ((word*)(Dest+i))[0] = ((word*)(Source+i))[0] ^ Key;
    }
}

void Add_Word(byte *Source, byte *Dest, word Key, word Len)
{
    int i;
    for (i=0;i<Len;i++)
    {
        ((word*)(Dest+i))[0] = ((word*)(Source+i))[0] + Key;
    }
}

word CutPast_File(dword DstOff, dword SrcOff, word Cut)
{
    int     rd;

    if ( (Cut > BU->File_Length) || (DstOff > SrcOff) )
        goto R_Fail;
    for (; SrcOff < BU->File_Length; SrcOff += BUFFER_SIZE, DstOff += BUFFER_SIZE)
    {
        if ((rd = Seek_Read(SrcOff,Buffer,BUFFER_SIZE)) == 0)
            goto R_Fail;
        if (Seek_Write(DstOff,Buffer,rd) != rd)
            goto R_Fail;
    }
    return Ch_Size(BU->File_Length - Cut);
    R_Fail:
        return R_FAIL;
}

word Cure_COM_Imm(byte *Buf, word Len, long New_Size)
{
    if (Seek_Write(0,Buf,Len) != Len)
        return R_FAIL;
    return Ch_Size(New_Size);
}

word Cure_EXE_Imm(byte *Exe_ip, byte *Exe_cs, byte *Exe_ss, byte *Exe_sp, long New_Size)
{
    HeaderExe->IP = ((word*)(Exe_ip))[0];
    HeaderExe->CS = ((word*)(Exe_cs))[0];
    if (Exe_ss != NULL)
        HeaderExe->SS = ((word*)(Exe_ss))[0];
    if (Exe_sp != NULL)
        HeaderExe->SP = ((word*)(Exe_sp))[0];

    HeaderExe->PartPag = New_Size & 0x1FF;
    HeaderExe->PageCnt = (word)(New_Size >> 9);
    if ( HeaderExe->PartPag )
        HeaderExe->PageCnt++;
    return Cure_COM_Imm(Header,0x18,BU->EP);
}

int Read_13(word R_CX, byte R_DH, void *buf)
{
#ifndef _WIN32
    struct  REGPACK regpack;
    byte    count_try;

    count_try = 5;
    regpack.r_flags |= 1;
    while (count_try && (regpack.r_flags&1) )
    {
        count_try--;
        regpack.r_ax = 0x201;
        regpack.r_cx = R_CX;
        regpack.r_dx = (R_DH<<8)|BU->Disk;
        regpack.r_bx = FP_OFF(buf);
        regpack.r_es = FP_SEG(buf);
        intr(0x13, &regpack);
    }
    return (regpack.r_flags&1)^1;
#else
    return 0;
#endif
}

int Write_13(word R_CX, byte R_DH, void *buf)
{
#ifndef _WIN32
    struct  REGPACK regpack;
    byte    count_try;

    count_try = 5;
    regpack.r_flags |= 1;
    while (count_try && (regpack.r_flags&1) )
    {
        count_try--;
        regpack.r_ax = 0x301;
        regpack.r_cx = R_CX;
        regpack.r_dx = (R_DH<<8)|BU->Disk;
        regpack.r_bx = FP_OFF(buf);
        regpack.r_es = FP_SEG(buf);
        intr(0x13, &regpack);
    }
    return (regpack.r_flags&1)^1;
#else
    return 0;
#endif
}

int Read_BOOTMBR(void *buf)
{
    return Read_13(1,0,buf);
}

int Write_BOOTMBR(void *buf)
{
    return Write_13(1,0,buf);
}

byte Rotate(void)
{
    static byte rotate[] = "-\\|/";
    static int r;
    byte c = 0;

    printf("%c\x08",rotate[r]);
    r++;
    r &= 3;

    if (BU->flag_notstop == 0 && kbhit())
    {
        c = getch();
        if (!c)
            getch();
        if (c == 0x1B || c == 0x20 || c == 0x0D )
        {
            printf("Cancel scan process ? (Yes/No) \n");
            c = getch();
            if (!c)
                getch();
            if ( (c|0x20) == 'y' || c == 0x0D)
                c = 0x1B;
            else
                c = 0;
        }
    }
    return c;
}

void Write_Page(char *Fname, void *buf, int count)
{
    int file;
    static char filename[64];
    char *pstr;

    if (BU->flag_pages && BU->Entry_Count < 10)
    {
        strcpy(filename,Fname);
        pstr = strrchr(filename,'.');
        if (pstr == NULL)
            strcat(filename,".pag");
        else
        {
            *(pstr-1) = BU->Entry_Count+'0';
            if ( !stricmp(pstr,".pag") )
                return;
        }
        strcpy(pstr,".pag");
        file = creat(filename,S_IWRITE);
        if ( file != -1 )
        {
            _write(file,buf,count);
            _close(file);
        }
    }
}

int Is_Program(char *Fname, byte *buf)
{
    char    *pstr ;

    if (BU->flag_all_files == 0)
    {
        pstr = strrchr(Fname,'.');
        if (pstr != NULL)
        {
            switch ( ((word*)(pstr+1))[0] | 0x2020)
            {
                case 0x6F63: case 0x7865: case 0x6162: case 0x7573: // coexsyba
                    goto Ret1;
            }
        }
        if (buf[0] == 0xE9 || buf[0] == 0xE8)
            goto Ret1;
        if ( ((word*)(buf))[0] == 'MZ' || ((word*)(buf))[0] == 'ZM')
            goto Ret1;
        return 0;
    }
Ret1:
    return 1;
}

void Copy_Data(void *dest, const void *src, size_t n)
{
     memcpy(dest,src,n);
}

void Fill_Data(void *dest, byte b, size_t n)
{
     memset(dest,b,n);
}

int Fill_Eof(dword file_length, byte *buffer, word size)
{
    if (file_length == 0)
        return 0;
    if (file_length < size)
    {
        Seek_Read(0,buffer+size-file_length,file_length);
    }
    else
    {
        Seek_Read(file_length-size,buffer,size);
    }
    return 1;
}

int Get_First_File_Entry(void)
{
    if ( (HeaderExe->Magic == 'MZ' || HeaderExe->Magic == 'ZM') && HeaderExe->PartPag < 0x200 )
    {
        BU->Sub_Type = ST_EXE;
        BU->EP = ((dword)(HeaderExe->HdrSize+HeaderExe->CS)*0x10+HeaderExe->IP)&0xFFFFFl;
        BU->Exe_IP = HeaderExe->IP;
    }
    else
    {
        if (Header[0] == 0xE9 || Header[0] == 0xE8 )
        {
            BU->EP = ((word*)(Header+1))[0]+3;
        }
        BU->Sub_Type = ST_COM;
        BU->Exe_IP = 0x100;
    }
    BU->Tail = BU->File_Length - BU->EP;
    Seek_Read(BU->EP,Buffer+0x2000,0x2000);
    Copy_Data(Jump1,Buffer+0x2000,JUMP1_SIZE);
    if (BU->EP < 0x2000)
    {
        Seek_Read(0,Buffer+0x2000-BU->EP,0x2000);
    }
    else
    {
        Seek_Read(BU->EP-0x2000,Buffer,0x2000);
    }
    BU->Redu_Length = 0;
    Fill_Eof(BU->File_Length,Eof,EOF_SIZE);
    if (BU->flag_redun)
        Fill_Eof(BU->File_Length,Redun,REDUN_SIZE);
    Seek(0L);
    return 1;
}

int Get_Next_File_Entry(void)
{
    if (BU->flag_redun && (++BU->Redu_Length < 0x200) )
    {
        Copy_Data(Eof,Redun+0x200-BU->Redu_Length,EOF_SIZE);
        BU->File_Length--;
        return 1;
    }       
    return 0;
}

int Get_First_Boot_Entry(void)
{
    switch (BU->Sub_Type)
    {
        case ST_MBR: case ST_BOOT:
            if (Read_BOOTMBR(Header) == 0)
            {
                BU->RFlags = 1;
                return 0;
            }
            break;
    }
    if (Header[0] == 0xE9 || Header[0] == 0xE8 )
    {
        BU->EP = ((word*)(Header+1))[0]+3;
    }
    if (Header[0] == 0xEB )
    {
        BU->EP = Header[1]+2;
    }
    Copy_Data(Jump1,Header,BU->EP);
    Copy_Data(Buffer,Header,BU->EP);
    return 1;
}

int Get_Next_Boot_Entry(void)
{
    return 0;
}

word Fill_Buffers(void)
{
    word    Result;

    Result = 0;
    BU->RFlags = 0;
    if (BU->Entry_Count == 0)
    {
        switch(BU->Object_Type)
        {
            case OT_FILE:
                Result = Get_First_File_Entry();
                break;
            case OT_SECTOR:
                Result = Get_First_Boot_Entry();
                break;
        }
    }
    else
    {
        switch(BU->Object_Type)
        {
            case OT_FILE:
                Result = Get_Next_File_Entry();
                break;
            case OT_SECTOR:
                Result = Get_Next_Boot_Entry();
                break;
        }
    }
    if (BU->RFlags == 1)
    {
        BU->Stat.Error++;
        Rprintf("%s\tI/O error\n", BU->Fname);
    }
    return Result;
}

void Show_vir_list(void)
{
    word        i;
    FILE_RECORD *Cur_Record;

    for (i=0,Cur_Record=AV_F->file_r;i<AV_F->file_records;i++,Cur_Record++)
    {
        Rprintf("%s\n",Cur_Record->virname);
    }
}

byte MBR_Data[512]=
{
0xFA,0x33,0xC0,0x8E, 0xD0,0xBC,0x00,0x7C, 0x8B,0xF4,0x50,0x07, 0x50,0x1F,0xFB,0xFC,
0xBF,0x00,0x06,0xB9, 0x00,0x01,0xF2,0xA5, 0xEA,0x1D,0x06,0x00, 0x00,0xBE,0xBE,0x07,
0xB3,0x04,0x80,0x3C, 0x80,0x74,0x0E,0x80, 0x3C,0x00,0x75,0x1C, 0x83,0xC6,0x10,0xFE,
0xCB,0x75,0xEF,0xCD, 0x18,0x8B,0x14,0x8B, 0x4C,0x02,0x8B,0xEE, 0x83,0xC6,0x10,0xFE,
0xCB,0x74,0x1A,0x80, 0x3C,0x00,0x74,0xF4, 0xBE,0x8B,0x06,0xAC, 0x3C,0x00,0x74,0x0B,
0x56,0xBB,0x07,0x00, 0xB4,0x0E,0xCD,0x10, 0x5E,0xEB,0xF0,0xEB, 0xFE,0xBF,0x05,0x00,
0xBB,0x00,0x7C,0xB8, 0x01,0x02,0x57,0xCD, 0x13,0x5F,0x73,0x0C, 0x33,0xC0,0xCD,0x13,
0x4F,0x75,0xED,0xBE, 0xA3,0x06,0xEB,0xD3, 0xBE,0xC2,0x06,0xBF, 0xFE,0x7D,0x81,0x3D,
0x55,0xAA,0x75,0xC7, 0x8B,0xF5,0xEA,0x00, 0x7C,0x00,0x00,0x49, 0x6E,0x76,0x61,0x6C,
0x69,0x64,0x20,0x70, 0x61,0x72,0x74,0x69, 0x74,0x69,0x6F,0x6E, 0x20,0x74,0x61,0x62,
0x6C,0x65,0x00,0x45, 0x72,0x72,0x6F,0x72, 0x20,0x6C,0x6F,0x61, 0x64,0x69,0x6E,0x67,
0x20,0x6F,0x70,0x65, 0x72,0x61,0x74,0x69, 0x6E,0x67,0x20,0x73, 0x79,0x73,0x74,0x65,
0x6D,0x00,0x4D,0x69, 0x73,0x73,0x69,0x6E, 0x67,0x20,0x6F,0x70, 0x65,0x72,0x61,0x74,
0x69,0x6E,0x67,0x20, 0x73,0x79,0x73,0x74, 0x65,0x6D,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x80,0x01,
0x01,0x00,0x06,0x0E, 0x16,0xFC,0x16,0x00, 0x00,0x00,0x0C,0x46, 0x01,0x00,0x00,0x00,
0x01,0xFD,0x05,0x0E, 0xD6,0xF1,0x22,0x46, 0x01,0x00,0xD2,0xCF, 0x03,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x55,0xAA
};

byte BOOT_Data[512]=
{
0xEB,0x28,0x90,0x49, 0x42,0x4D,0x20,0x50, 0x4E,0x43,0x49,0x00, 0x02,0x01,0x01,0x00,
0x02,0xE0,0x00,0x40, 0x0B,0xF0,0x09,0x00, 0x12,0x00,0x02,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0xFA,0x33, 0xC0,0x8E,0xD0,0xBC,
0xF0,0x7B,0xFB,0xB8, 0xC0,0x07,0x8E,0xD8, 0xBE,0x5C,0x00,0x90, 0x90,0xFC,0xAC,0x0A,
0xC0,0x74,0x0B,0x56, 0xB4,0x0E,0xBB,0x07, 0x00,0xCD,0x10,0x5E, 0xEB,0xF0,0x32,0xE4,
0xCD,0x16,0xB4,0x0F, 0xCD,0x10,0x32,0xE4, 0xCD,0x10,0xCD,0x19, 0x0D,0x0A,0x0D,0x0A,
0x0D,0x0A,0x0D,0x0A, 0x0D,0x0A,0x0D,0x0A, 0x0D,0x0A,0x0D,0x0A, 0x20,0x20,0x20,0x20,
0x54,0x68,0x69,0x73, 0x20,0x64,0x69,0x73, 0x6B,0x20,0x69,0x73, 0x20,0x6E,0x6F,0x74,
0x20,0x62,0x6F,0x6F, 0x74,0x61,0x62,0x6C, 0x65,0x0D,0x0A,0x0D, 0x0A,0x20,0x49,0x66,
0x20,0x79,0x6F,0x75, 0x20,0x77,0x69,0x73, 0x68,0x20,0x74,0x6F, 0x20,0x6D,0x61,0x6B,
0x65,0x20,0x69,0x74, 0x20,0x62,0x6F,0x6F, 0x74,0x61,0x62,0x6C, 0x65,0x2C,0x0D,0x0A,
0x72,0x75,0x6E,0x20, 0x74,0x68,0x65,0x20, 0x44,0x4F,0x53,0x20, 0x70,0x72,0x6F,0x67,
0x72,0x61,0x6D,0x20, 0x53,0x59,0x53,0x20, 0x61,0x66,0x74,0x65, 0x72,0x20,0x74,0x68,
0x65,0x0D,0x0A,0x20, 0x20,0x20,0x20,0x20, 0x73,0x79,0x73,0x74, 0x65,0x6D,0x20,0x68,
0x61,0x73,0x20,0x62, 0x65,0x65,0x6E,0x20, 0x6C,0x6F,0x61,0x64, 0x65,0x64,0x0D,0x0A,
0x0D,0x0A,0x50,0x6C, 0x65,0x61,0x73,0x65, 0x20,0x69,0x6E,0x73, 0x65,0x72,0x74,0x20,
0x61,0x20,0x44,0x4F, 0x53,0x20,0x64,0x69, 0x73,0x6B,0x65,0x74, 0x74,0x65,0x20,0x69,
0x6E,0x74,0x6F,0x0D, 0x0A,0x20,0x74,0x68, 0x65,0x20,0x64,0x72, 0x69,0x76,0x65,0x20,
0x61,0x6E,0x64,0x20, 0x73,0x74,0x72,0x69, 0x6B,0x65,0x20,0x61, 0x6E,0x79,0x20,0x6B,
0x65,0x79,0x2E,0x2E, 0x2E,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x55,0xAA
};

int Overwrite_Sector(void)
{
    switch (BU->Sub_Type)
    {
        case ST_MBR:
            Copy_Data(Header,MBR_Data,0x1BE);
            ((word*)(Header+0x1FE))[0] = 0xAA55;
            return Write_BOOTMBR(Header);
        case ST_BOOT:
            Copy_Data(Jump1, BOOT_Data, 512);
            Copy_Data(Jump1+0x0D,Header+0x0D,0x28-0x0D);
            Jump1[0x10]&=0x0F;
            Jump1[0x15]|=0xF0;
            Jump1[0x1B] = Jump1[0x1F] = Jump1[0x21] = 0;
            return Write_BOOTMBR(Jump1);
    }
    return 0;
}

word Delete_File(void)
{
    word    Result;

    Result = R_FAIL;
    _close(BU->OpenedFile);
    #ifdef _WIN32
        SetFileAttributes(BU->Fname,0);
    #else
        _dos_setfileattr(BU->Fname,0);
    #endif
    if (remove(BU->Fname)==0)
    {
        Result = R_DELETE;
        BU->Stat.Deleted++;
    }
    return Result;
}

word Scan_Sector(void)
{
    word    i;
    word    Result;
    SECTOR_RECORD   *Cur_Record;

    Result = R_CLEAN;
    for (i=0,Cur_Record=AV_F->sector_r;i<AV_F->sector_records;i++,Cur_Record++)
    {
            if (Cur_Record->len_crc1 == 0 || Cur_Record->check_dword == ((dword*)(Header+(Cur_Record->offset1) ))[0])
            {
                if (Cur_Record->len_crc1 != 0 && Cur_Record->crc1 == 0l)
                {
                    Rprintf("\r%s\n",BU->Fname);
                    Rprintf("Check dword is: %08lX\n", ((dword*)(Header+(Cur_Record->offset1) ))[0] );
                    Rprintf("Crc1 is:(%02X->%04X) %08lX\n", Cur_Record->len_crc1, Cur_Record->offset1,
                        calc_crc(Header+Cur_Record->offset1,Cur_Record->len_crc1) );
                }
                if (Cur_Record->len_crc1 == 0 || calc_crc(Header+Cur_Record->offset1,Cur_Record->len_crc1) ==
                    Cur_Record->crc1)
                {
                    Result = (Cur_Record->len_crc1 > 7) ? R_WARNING : R_PREDETECT;
                    if (Cur_Record->decode != NULL)
                    {
                        Result = Cur_Record->decode();
                    }
                    if (Result == R_WARNING || Result == R_PREDETECT)
                    {
                        if (calc_crc(Header+Cur_Record->offset2,Cur_Record->len_crc2) ==
                            Cur_Record->crc2)
                        {
                            Result = R_DETECT;
                        }
                    }
                }
                if (Cur_Record->len_crc2 != 0 && Cur_Record->crc2 == 0l)
                {
                    Rprintf("\r%s\n",BU->Fname);
                    Rprintf("Crc2 is:(%02X->%04X) %08lX\n", Cur_Record->len_crc2, Cur_Record->offset2,
                        calc_crc(Header+Cur_Record->offset2,Cur_Record->len_crc2) );
                }
                if (Result == R_WARNING)
                {
                    BU->Stat.Warnings++;
                    Rprintf("%s",BU->Fname);
                    Rprintf("\twarning: %s\n", Cur_Record->virname);
                }
                if (Result == R_DETECT)
                {
                    BU->Stat.Infected++;
                    Rprintf("%s",BU->Fname);
                    Rprintf("\tinfected: %s\n", Cur_Record->virname);
                    if (BU->flag_cure)
                    {
                        Result = R_FAIL;
                        Rprintf("%s",BU->Fname);
                        if (BU->Object_Type == OT_FILE)
                        {
                            Result = Delete_File();
                            if (Result == R_DELETE)
                                Rprintf("\tdeleted: %s\n", Cur_Record->virname);
                            else
                                Rprintf("\tdisinfection error: %s\n", Cur_Record->virname);
                            break;
                        }
                        if (Cur_Record->cure != NULL)
                        {
                            Result = Cur_Record->cure();
                            if ( Result == R_PRECURE)
                            {
                                if (Write_BOOTMBR(Header))
                                    Result = R_CURE;
                                else
                                    Result = R_FAIL;
                            }
                            switch (Result)
                            {
                                case R_CURE:
                                    BU->Stat.Disinfected++;
                                    Rprintf("\tdisinfected: %s\n", Cur_Record->virname);
                                    break;
                                case R_DELETE:
                                    // BU->Stat.Deleted++;
                                    if (Overwrite_Sector())
                                    {
                                        Rprintf("\tdeleted: %s\n", Cur_Record->virname);
                                        break;
                                    }                                   
                                    // Skip break
                                case R_FAIL:
                                    Rprintf("\tdisinfection failed: %s\n", Cur_Record->virname);
                                    break;
                                default:
                                    Rprintf("\tdisinfection error: %s\n", Cur_Record->virname);
                                    break;
                            }
                        }
                        else
                        {
                            Rprintf("\tdisinfection skipped: %s\n", Cur_Record->virname);
                        }
                    }
                    break;
                }
            }
    }
    return Result;
}

word Scan_File(void)
{
    word    i;
    word    Result;
    FILE_RECORD *Cur_Record;

    Result = R_CLEAN;
    for (i=0,Cur_Record=AV_F->file_r;i<AV_F->file_records;i++,Cur_Record++)
    {
        if ( (Cur_Record->sub_type & BU->Sub_Type) != 0)
        {
            if (Cur_Record->len_crc1 == 0 || Cur_Record->check_dword == ((dword*)(Header+(Cur_Record->offset1) ))[0])
            {
                if (Cur_Record->len_crc1 != 0 && Cur_Record->crc1 == 0l)
                {
                    Rprintf("\r%s\n",BU->Fname);
                    Rprintf("Check dword is: %08lX\n", ((dword*)(Header+(Cur_Record->offset1) ))[0] );
                    Rprintf("Crc1 is:(%02X->%04X) %08lX\n", Cur_Record->len_crc1, Cur_Record->offset1,
                        calc_crc(Header+Cur_Record->offset1,Cur_Record->len_crc1) );
                }
                if (Cur_Record->len_crc1 == 0 || calc_crc(Header+Cur_Record->offset1,Cur_Record->len_crc1) ==
                    Cur_Record->crc1)
                {
                    Result = (Cur_Record->len_crc1 > 7) ? R_WARNING : R_PREDETECT;
                    if (Cur_Record->decode != NULL)
                    {
                        Result = Cur_Record->decode();
                    }
                    if (Result == R_WARNING || Result == R_PREDETECT)
                    {
                        if (calc_crc(Header+Cur_Record->offset2,Cur_Record->len_crc2) ==
                            Cur_Record->crc2)
                        {
                            Result = R_DETECT;
                        }
                    }
                }
                if (Cur_Record->len_crc2 != 0 && Cur_Record->crc2 == 0l)
                {
                    Rprintf("\r%s\n",BU->Fname);
                    Rprintf("Crc2 is:(%02X->%04X) %08lX\n", Cur_Record->len_crc2, Cur_Record->offset2,
                        calc_crc(Header+Cur_Record->offset2,Cur_Record->len_crc2) );
                }
                if (Result == R_WARNING)
                {
                    BU->Stat.Warnings++;
                    Rprintf("%s",BU->Fname);
                    Rprintf("\twarning: %s\n", Cur_Record->virname);
                }
                if (Result == R_DETECT)
                {
                    BU->Stat.Infected++;
                    Rprintf("%s",BU->Fname);
                    Rprintf("\tinfected: %s\n", Cur_Record->virname);
                    if (BU->flag_delinf)
                    {
                        Result = Delete_File();
                        Rprintf("%s",BU->Fname);
                        if (Result == R_DELETE)
                        {
                            Rprintf("\tdeleted: %s\n", Cur_Record->virname);
                        }
                        else
                        {
                            Rprintf("\tdisinfection error: %s\n", Cur_Record->virname);
                        }
                        break;
                    }
                    if (BU->flag_cure)
                    {
                        Result = R_FAIL;
                        _close(BU->OpenedFile);
                        #ifdef _WIN32
                            SetFileAttributes(BU->Fname,0);
                        #else
                            _dos_setfileattr(BU->Fname,0);
                        #endif
                        if ( (BU->OpenedFile = openFile(BU->Fname,O_RDWR|O_BINARY)) != -1 )
                        {
                            Rprintf("%s",BU->Fname);
                            if (Cur_Record->cure != NULL)
                            {
                                Result = Cur_Record->cure();
                                if ( Result == R_PRECURE)
                                {
                                    Result = Ch_Size(BU->EP);
                                }
                                switch (Result)
                                {
                                    case R_CURE:
                                        BU->Stat.Disinfected++;
                                        Rprintf("\tdisinfected: %s\n", Cur_Record->virname);
                                        break;
                                    case R_DELETE:
                                        Result = Delete_File();
                                        if ( Result == R_DELETE)
                                        {
                                            Rprintf("\tdeleted: %s\n", Cur_Record->virname);
                                        }
                                        break;
                                    case R_FAIL:
                                        Rprintf("\tdisinfection failed: %s\n", Cur_Record->virname);
                                        break;
                                    default:
                                        Rprintf("\tdisinfection error: %s\n", Cur_Record->virname);
                                        break;
                                }
                            }
                            else
                            {
                                Rprintf("\tdisinfection skipped: %s\n", Cur_Record->virname);
                            }
                        }
                        else
                        {
                            BU->Stat.Error++;
                            Rprintf("%s\tI/O error\n", BU->Fname);
                        }
                    }
                    break;
                }
            }
        }
    }
    return Result;
}

word Check_File(char * Fname)
{
    word    Result;

    BU->Object_Type = OT_FILE;

    Check_More:
    Result = R_FAIL;
    if (Rotate() == 0x1B)
    {
        BU->flag_stop_scan = 1;
        Rprintf("Scan terminate...\n");
        return Result;
    }
    if ( (BU->OpenedFile = openFile(Fname,O_RDONLY|O_BINARY)) != -1 )
    {
        BU->EP = BU->Entry_Count = 0;
        BU->File_Length = filelength(BU->OpenedFile);
        strcpy(BU->Fname,Fname);
        memset(Header,0x0F,ALL_SIZE);

        Seek_Read(0,Header,HEADER_SIZE);
        if (Is_Program(Fname, Header) != 0)
        {
            Result = R_CLEAN;
            BU->Stat.Checked++;
            while (Fill_Buffers() && Result == R_CLEAN )
            {
                Result = Scan_File();
                if (Result == R_CLEAN)
                {
                    Result = Scan_Sector();
                }
                Write_Page(Fname,Header,ALL_SIZE);
                BU->Entry_Count++;
            }
            if (Result == R_CLEAN && BU->flag_ok && BU->RFlags == 0)
            {
                Rprintf("%s\tok.\n",BU->Fname);
            }
        }
        _close(BU->OpenedFile);
        if (Result == R_CURE)
            goto Check_More;
    }
    else
    {
        BU->Stat.Error++;
        Rprintf("%s\tI/O error\n", Fname);
    }
    return Result;
}

#ifndef _WIN32
word Scan_Mem(word Memory_Seg)
{
    word    i;
    word    Result;
    MEM_RECORD  *Cur_Record;

    Result = R_CLEAN;
    for (i=0,Cur_Record=AV_F->mem_r;i<AV_F->mem_records;i++,Cur_Record++)
    {

        if (Cur_Record->sub_type == BU->Sub_Type)
        {
            if (BU->Sub_Type == ST_ADDRESS)
            {
                Memory_Seg = Cur_Record->segment1;
            }
            if (Cur_Record->len_crc1 && (Cur_Record->check_dword == 0l) )
            {
                Rprintf("%04X:%04X\n",Memory_Seg,Cur_Record->offset1);
                Rprintf("Check dword is: %08lX\n", ((dword FAR*)( MK_FP( Memory_Seg, Cur_Record->offset1) ))[0] );
                Rprintf("Crc1 is:(%02X->%04X) %08lX\n", Cur_Record->len_crc1, Cur_Record->offset1,
                    calc_crc(MK_FP(Memory_Seg, Cur_Record->offset1),Cur_Record->len_crc1) );
            }
            if (Cur_Record->len_crc1 == 0 || Cur_Record->check_dword == ((dword FAR*)( MK_FP(Memory_Seg, Cur_Record->offset1) ))[0] )
            {
                _fmemcpy(Buffer, MK_FP(Memory_Seg, Cur_Record->offset1),Cur_Record->len_crc1);
                if (calc_crc(Buffer, Cur_Record->len_crc1) == Cur_Record->crc1)
                {
                    Result = R_DETECT;
                    if (Cur_Record->decode != NULL)
                    {
                        Result = Cur_Record->decode();
                    }
                }
                if (Result == R_DETECT)
                {
                    Rprintf("%04X:%04X",Memory_Seg, Cur_Record->offset1);
                    Rprintf("\tinfected: %s\n", Cur_Record->virname);
                    {
                        Rprintf("%04X:%04X",Memory_Seg, Cur_Record->offset1);
                        Result = R_FAIL;
                        if (Cur_Record->cure != NULL)
                        {
                            Result = Cur_Record->cure();
                            if ( Result == R_CURE)
                            {
                                Rprintf("\tdisinfected: %s\n", Cur_Record->virname);
                            }
                            else
                            {
                                Rprintf("\tdisinfection failed: %s\n", Cur_Record->virname);
                            }
                        }
                        else
                        {
                            _fmemcpy( MK_FP(Memory_Seg, Cur_Record->cure_off),
                                        MK_FP( FP_SEG(Cur_Record), FP_OFF(Cur_Record->cure_data+1) ),
                                         Cur_Record->cure_data[0] );
                            Rprintf("\tdisinfected: %s\n", Cur_Record->virname);
                        }
                    }
                    // skip break
                }
            }
        }
    }
    return Result;
}

word Check_Mem(void)
{
    struct  REGPACK regpack;
    word    FAR *mem_ptr, save_ptr;
    byte    FAR *mcb_ptr;
    word    Result;

    Result = R_FAIL;
    if (BU->flag_mem == 0)
    {
        Result = R_CLEAN;
        BU->Object_Type = OT_MEMORY;
        BU->Sub_Type = ST_MCB;
        regpack.r_ax = 0x5200;
        intr(0x21,&regpack);
        mem_ptr = MK_FP(regpack.r_es,regpack.r_bx-2);
        mcb_ptr = MK_FP( *mem_ptr, 0);

        // Scan main memory
        while ( mcb_ptr[0] == 'M' )
        {
            Scan_Mem( FP_SEG(mcb_ptr)+1 );
            mcb_ptr = MK_FP( FP_SEG(mcb_ptr)+((word FAR*)(mcb_ptr+3))[0]+1,0);
        }
        if ( mcb_ptr[0] == 'Z' )
        {
            Scan_Mem( FP_SEG(mcb_ptr)+1 );
            mcb_ptr = MK_FP( FP_SEG(mcb_ptr)+((word FAR*)(mcb_ptr+3))[0]+1,0);
        }
        save_ptr = FP_SEG(mcb_ptr);
        // Scan UMB memory
        while ( mcb_ptr[0] == 'M' )
        {
            Scan_Mem( FP_SEG(mcb_ptr)+1 );
            mcb_ptr = MK_FP( FP_SEG(mcb_ptr)+((word FAR*)(mcb_ptr+3))[0]+1,0);
        }
        if ( mcb_ptr[0] == 'Z' )
        {
            Scan_Mem( FP_SEG(mcb_ptr)+1 );
        }
        // Scan cuted memory
        for (;save_ptr<0xA000;save_ptr++)
        {
            Scan_Mem( save_ptr );
        }
        // Scan cuted 0x413 memory
        BU->Sub_Type = ST_CUT;
        mem_ptr = MK_FP(0,0x413);
        save_ptr = (*mem_ptr)<<6;
        for (;save_ptr<0xA000;save_ptr++)
        {
            Scan_Mem( save_ptr );
        }
        // Check INT Table memory
        BU->Sub_Type = ST_ADDRESS;
        Scan_Mem( 0 );
    }
    return Result;
}

word Check_Sect(void)
{
    word Result;

    if (BU->flag_boot == 0)
    {
    Check_More:
        Result = R_CLEAN;
        BU->EP = BU->Entry_Count = 0;
        BU->Object_Type = OT_SECTOR;
        memset(Header,0x0F,ALL_SIZE);
        switch(BU->Disk)
        {
            case 0:
                BU->Sub_Type = ST_BOOT;
                strcpy(BU->Fname,"A:  ฐ Boot Sector:");
                break;
            case 1:
                BU->Sub_Type = ST_BOOT;
                strcpy(BU->Fname,"B:  ฐ Boot Sector:");
                break;
            case 0x80:
                BU->Sub_Type = ST_MBR;
                strcpy(BU->Fname,"HDD1ฐ Master Boot Record:");
                break;
            default:
                goto R_Clean;
        }
        while (Fill_Buffers() && Result == R_CLEAN )
        {
            BU->Stat.Sector++;
            Result = Scan_Sector();
            Write_Page("sector.dat",Header,ALL_SIZE);
            BU->Entry_Count++;
        }
        if (Result == R_CLEAN && BU->flag_ok && BU->RFlags == 0)
        {
            Rprintf("%s\tok.\n",BU->Fname);
        }
        if (Result == R_CURE)
            goto Check_More;
    }
    R_Clean:
    return Result;
}
#endif

#ifdef WIN32
void add_data_time(char *Fmt)
{
    char tmp_str[200];
    SYSTEMTIME lp;
    GetLocalTime(&lp);
    sprintf(tmp_str,Fmt,lp.wYear,lp.wMonth,lp.wDay,lp.wHour,lp.wMinute,lp.wSecond);
    Roprintf(tmp_str);
}
#else
void add_data_time(char *Fmt)
{
    struct  date d;
    struct  time t;
    char    tmp_str[200];
    getdate(&d);
    gettime(&t);
    sprintf(tmp_str,Fmt,d.da_year,d.da_mon,d.da_day,t.ti_hour,t.ti_min,t.ti_sec);
    Roprintf(tmp_str);
}
#endif

int main(int argc, char *argv[])
{
    int i;
    char *P_Key;
    char *StartMes =
 "ฺฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฟ\n"
 "ณ    Silly Antivirus for DOS16/WIN32      บ\n"
 "ณ Copyright(C) Valentin Kolesnikov 1999   บ  Support: E-mail:\n"
 "ณ        Version 1.0  build 021           บ  javadev75@gmail.com\n"
 "ภอออออออออออออออออออออออออออออออออออออออออผ\n\n";

    memset(BU,0,sizeof(BUFFER));

    printf(StartMes);

    for (i=1;i<argc;i++)
    {
        if ( argv[i][0] == '/' || argv[i][0] == '-' )
        {
            P_Key = argv[i]+1;
            if (!stricmp(P_Key,"*") )
            {
                BU->flag_all_files = 1;
                continue;
            }
            if (!stricmp(P_Key,"-") )
            {
                BU->flag_cure = 1;
                continue;
            }
            if (!stricmp(P_Key,"o") )
            {
                BU->flag_ok = 1;
                continue;
            }
            if (!stricmp(P_Key,"p") )
            {
                BU->flag_pages = 1;
                continue;
            }
            if (!stricmp(P_Key,"r") )
            {
                BU->flag_subdir = 1;
                continue;
            }
            if (!stricmp(P_Key,"l") )
            {
                BU->flag_list = 1;
                continue;
            }
            if (!stricmp(P_Key,"b") )
            {
                BU->flag_boot = 1;
                continue;
            }
            if (!stricmp(P_Key,"m") )
            {
                BU->flag_mem = 1;
                continue;
            }
            if (!stricmp(P_Key,"e") )
            {
                BU->flag_delinf = 1;
                continue;
            }
            if (!stricmp(P_Key,"z") )
            {
                BU->flag_notstop = 1;
                continue;
            }
            if (!stricmp(P_Key,"v") )
            {
                BU->flag_redun = 1;
                continue;
            }
            if (!strnicmp(P_Key,"w",1))
            {
                BU->flag_rep = 1;
                if (P_Key[1])
                {
                    strcpy(BU->Repname,P_Key+2);
                }
                if (strlen(BU->Repname) == 0)
                {
                    strcpy(BU->Repname,"sillyav.log");
                }
                if ( (BU->ReportHandle = fopen(BU->Repname, "w+t")) == NULL)
                {
                    BU->flag_rep = 0;
                }
                continue;
            }
            Rprintf("Unknown key : %s\n",argv[i]);
        }
    }

    Roprintf(StartMes);
    add_data_time("Report was created at date: %04d/%02d/%02d, time: %02d:%02d:%02d\n");
    Roprintf("Command line :");
    for (i=1;i<argc;i++)
    {
        Roprintf(" %s",argv[i]);
    }
    Roprintf("\n\n");

    Rprintf("Loading database, AV records : ");
    InitCRC();
    Rprintf("%d\n", AV_F->total_records);

    if (BU->flag_list)
    {
        Rprintf("Virus list ...\n");
        Show_vir_list();
    }
    if ( argc >= 2 )
    {
        #ifndef _WIN32
            Rprintf("Scanning memory ...\n");
            Check_Mem();
            BU->Disk = 0x80;
            Check_Sect();
        #endif
        if (Check_File(argv[0]) == R_CLEAN)
            BU->Stat.Checked--;
        for (i=1;i<argc;i++)
        {
            if (argv[i][0] != '/' && argv[i][0] != '-')
            {
                Rprintf("Processing %s\n",argv[i]);
                #ifndef _WIN32
                    if (argv[i][1] == ':' &&
                        ( (argv[i][0]|0x20) == 'a' || (argv[i][0]|0x20) == 'b') )
                    {
                        BU->Disk = (argv[i][0]|0x20)-'a';
                        Check_Sect();
                    }
                #endif
                scan_path(argv[i]);
            }
        }
        Rprintf("\nScanned\n"
               "Sectors:     %8lu\n",BU->Stat.Sector);
        Rprintf("Files:       %8lu\n",BU->Stat.Checked);
        Rprintf("Folders:     %8lu\n",BU->Stat.Folder);
        Rprintf("\nFound\n"
               "Infected:    %8lu\n",BU->Stat.Infected);
        Rprintf("Warnings:    %8lu\n",BU->Stat.Warnings);
        Rprintf("Disinfected: %8lu\n",BU->Stat.Disinfected);
        Rprintf("Deleted:     %8lu\n",BU->Stat.Deleted);
        Rprintf("I/O Errors:  %8lu\n",BU->Stat.Error);
        add_data_time("\nScan process was stopped at date: %04d/%02d/%02d, time: %02d:%02d:%02d\n");
    }
    else
    {
        #ifdef _WIN32
            printf("Usage: Sillav32 Fname|Path /Keys\n");
        #else
            printf("Usage: Sillav16 Fname|Path /Keys\n");
        #endif
        printf(
             "    /*  scan all files\n"
             "    /-  disinfect\n"
             "    /E  delete infected files\n"
             "    /L  make virus list\n"
             "    /O  display OK messages\n"
             "    /R  do not scan subdirectories\n"
             "    /B  do not scan sectors (32-bit by default)\n"
             "    /M  do not scan memory (32-bit by default)\n"
             "    /V  enable redundant scanning\n"
             "    /W[=filename]  save report\n"
             "    /Z  disable aborting\n"
             "    /P  save pages.\n");
    }
    if (BU->Stat.Infected)
    {
        if (BU->Stat.Infected == BU->Stat.Disinfected)
            return 5;
        else
            return 4;
    }
    if (BU->Stat.Warnings)
    {
        return 3;
    }
    return 0;
}
