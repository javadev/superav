/* Silly ANTIVIRUS Version 1.0 build 021                        */
/* Written by Valentin Kolesnikov, e-mail: javadev75@gmail.com  */

#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <dos.h>
#include <fcntl.h>
#include <sys\stat.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "sillyav.h"
#define CCHMAXPATH 0x200

extern word Check_File(char *fname);

char  szFilename[CCHMAXPATH+1],szFullFileName[CCHMAXPATH+1];

typedef struct find_t FIND_T;
void scan_path(char *CurrDir)
{
    byte    Save_flag;
#ifndef WIN32
    struct find_t mffblk;
    struct find_t tmpMffblk;
#else
    HANDLE hf;
    WIN32_FIND_DATA fd;
    WIN32_FIND_DATA fdTmp;
#endif

#ifdef WIN32
    fd.dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM;
    hf = FindFirstFile(CurrDir,&fd);
    if ( hf != INVALID_HANDLE_VALUE)
        if ( !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
#else
    if ( _dos_findfirst(CurrDir,FA_RDONLY|FA_HIDDEN|FA_SYSTEM|FA_ARCH,&mffblk) == 0)
        if ( !(mffblk.attrib&0x10) )
        {
#endif
            Save_flag = BU->flag_all_files;
            BU->flag_all_files = 1;
            // File found
            Check_File(CurrDir);
            BU->flag_all_files = Save_flag;
        }
#ifdef WIN32
    FindClose(hf);
#endif

    if ( CurrDir[strlen(CurrDir)-1] == '\\')
    {
        sprintf(szFilename,"%s*.*",CurrDir);
    }
    else
    {
        sprintf(szFilename,"%s\\*.*",CurrDir);
    }
#ifdef WIN32
    fd.dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_DIRECTORY;
    hf = FindFirstFile(szFilename,&fd);
    if ( hf != INVALID_HANDLE_VALUE && BU->flag_stop_scan == 0)
#else
    if ( _dos_findfirst(szFilename,0x37,&mffblk) == 0 && BU->flag_stop_scan == 0)
#endif
    {
        BU->Stat.Folder++;
        do
        {
#ifdef WIN32
            if ( strcmp(fd.cFileName,".") && strcmp(fd.cFileName,"..") )
            {
            if ( (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) )
#else
            if (  strcmp(mffblk.name, ".") && strcmp(mffblk.name, "..") )
            {
            if ( (mffblk.attrib&0x10) )
#endif
                {
                    if ( BU->flag_subdir == 0 )
                    {
                        char tempDir[CCHMAXPATH+1];
                        if ( CurrDir[strlen(CurrDir)-1] == '\\')
                        {
#ifdef WIN32
#ifdef SHORT_NAME
                        if ( CurrDir,fd.cAlternateFileName[0] != 0)
                            sprintf(tempDir,"%s%s",CurrDir,fd.cAlternateFileName);
                        else
#endif
                            sprintf(tempDir,"%s%s",CurrDir,fd.cFileName);
#else
                            sprintf(tempDir,"%s%s",CurrDir,mffblk.name);
#endif
                        }
                        else
                        {
#ifdef WIN32
#ifdef SHORT_NAME
                            if ( CurrDir,fd.cAlternateFileName[0] != 0)
                                sprintf(tempDir,"%s\\%s",CurrDir,fd.cAlternateFileName);
                            else
#endif
                                sprintf(tempDir,"%s\\%s",CurrDir,fd.cFileName);
#else
                            sprintf(tempDir,"%s\\%s",CurrDir,mffblk.name);
#endif
                        }
#ifdef WIN32
                        memcpy(&fdTmp,&fd,sizeof(WIN32_FIND_DATA));
                        scan_path(tempDir);
                        memcpy(&fd,&fdTmp,sizeof(WIN32_FIND_DATA));
#else
                        memcpy(&tmpMffblk,&mffblk,sizeof(FIND_T));
                        scan_path(tempDir);
                        memcpy(&mffblk,&tmpMffblk,sizeof(FIND_T));
#endif
                    }
                }
                else
                {
                    if ( CurrDir[strlen(CurrDir)-1] == '\\')
                    {
#ifdef WIN32
#ifdef SHORT_NAME
                        if ( CurrDir,fd.cAlternateFileName[0] != 0)
                            sprintf(szFullFileName,"%s%s",CurrDir,fd.cAlternateFileName);
                        else
#endif
                            sprintf(szFullFileName,"%s%s",CurrDir,fd.cFileName);
#else
                        sprintf(szFullFileName,"%s%s",CurrDir,mffblk.name);
#endif
                    }
                    else
                    {
#ifdef WIN32
#ifdef SHORT_NAME
                        if ( CurrDir,fd.cAlternateFileName[0] != 0)
                            sprintf(szFullFileName,"%s\\%s",CurrDir,fd.cAlternateFileName);
                        else
#endif
                            sprintf(szFullFileName,"%s\\%s",CurrDir,fd.cFileName);
#else
                        sprintf(szFullFileName,"%s\\%s",CurrDir,mffblk.name);
#endif
                    }
                    // File found
                    Check_File(szFullFileName);
                }
            }
#ifdef WIN32
        } while(FindNextFile(hf,&fd) != 0 && BU->flag_stop_scan == 0);
#else
        } while(_dos_findnext(&mffblk) == 0 && BU->flag_stop_scan == 0);
#endif
    }
#ifdef WIN32
    FindClose(hf);
#endif
}
