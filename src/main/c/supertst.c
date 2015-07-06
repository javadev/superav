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

#include "superav.h"

word decode_vpp681(void)
{
    word    key;

    ((byte*)(&key))[0] = Eof[0x625];
    ((byte*)(&key))[1] = Eof[0x62E];
    Xor_Word(Eof+0x597,Buffer,key,0x43);
    return R_PREDETECT;
}

word cure_vpp(word Bytes, word Size)
{
    int i;
    dword   Call_Tail;

    for (i=0;i<0x3F0;i++)
    {
        if (Header[i] == 0xE8)
        {
            Call_Tail = BU->File_Length - ( ((word*)(Header+i+1))[0] + i +3 );
            if (Call_Tail == Size)
            {
                if (Seek_Write(i,Eof+Bytes,3) != 3)
                    break;
                return Ch_Size(BU->File_Length-Size);
            }
        }
    }
    return R_FAIL;
}

word cure_vpp475(void)
{
    return cure_vpp(0x7F8,475);
}

word cure_vpp681(void)
{
    word    key;

    ((byte*)(&key))[0] = Eof[0x625];
    ((byte*)(&key))[1] = Eof[0x62E];
    Xor_Word(Eof+0x597,Buffer,key,0x266);
    return cure_vpp(EOF_SIZE+0x263,681);
}

word decode_redar(void)
{
    int i;
    word    key1, key2;

    key1 = ((word*)(Eof))[0] ^ 0x0333;
    key2 = ((word*)(Eof))[1] ^ 0xAB93;
    for (i=0;i<0x40;i+=4)
    {
        ((word*)(Buffer+i))[0] = ((word*)(Eof+i))[0] ^ key1;
        ((word*)(Buffer+i+2))[0] = ((word*)(Eof+i+2))[0]^ key2;
    }
    return R_PREDETECT;
}

word cure_redar(void)
{
    int i;
    word    key1, key2;

    key1 = ((word*)(Eof))[0] ^ 0x0333;
    key2 = ((word*)(Eof))[1] ^ 0xAB93;
    for (i=0x7F8;i<EOF_SIZE;i+=4)
    {
        ((word*)(Buffer+i))[0] = ((word*)(Eof+i))[0] ^ key1;
        ((word*)(Buffer+i+2))[0] = ((word*)(Eof+i+2))[0]^ key2;
    }
    Seek_Read(BU->File_Length-0x800-0x5C8,Buffer+0x800,2);
    ((word*)(Buffer+0x800))[0] ^= key1;
    ((word*)(Buffer+0x7FC))[0] ^= ((word*)(Buffer+0x800))[0];

    if (Seek_Write( ((word*)(Buffer+0x7F8))[0] - 0x100, Buffer+0x7FA, 3 ) == 3)
        return Ch_Size( BU->File_Length-3529 );

    return R_FAIL;
}

word cure_vpp1216(void)
{
    Buffer[0] = Eof[0x340+0x3B];
    Buffer[1] = Eof[0x340+0x3C];
    Buffer[2] = Eof[0x340+0x3F];
    Seek_Write(0,Buffer,3);
    return R_PRECURE;
}

word decode_samar(void)
{
    word    ptr, Offset, Events = 0, Inst_count = 0;

    if (BU->Tail < 1400 || BU->Tail > 1700)
        goto R_Clean;
    for (ptr=0;ptr<0x20;ptr++)
    {
        Inst_count++;
        //DEBUG(("\nptr %04X -> %02X %02X %02X %02X", ptr, Jump1[ptr], Jump1[ptr+1], Jump1[ptr+2], Jump1[ptr+3]));
        switch (Jump1[ptr])
        {
            case 0x26: case 0x2E: case 0x36: case 0x3E: case 0x44:
                Events++;
                break;
            case 0x80:
                ptr += 4;
                Events++;
                break;
            case 0x81:
                ptr += 5;
                Events++;
                break;
            case 0xFF:
                if (Jump1[ptr+1] == 0x06)
                    ptr += 3;
                Events++;
                break;
            case 0x72: case 0x75:
                Events++;
                goto Decode_vir;
            default:
                goto R_Clean;
        }
    }
R_Clean:
    return R_CLEAN;

Decode_vir:
    Offset = ptr+2;
    if (Inst_count > 10  && Events > 10)
    {
        if ( (Jump1[Offset+0x11] ^ Jump1[Offset+0x62]) == 0xFF)
            Xor_Byte(Jump1+Offset,Buffer,Jump1[Offset+0x11],0x43);
        else
            Add_Byte(Jump1+Offset,Buffer,(byte)(-Jump1[Offset+0x11]),0x43);
        ((word*)(Buffer))[0] = Offset;
        return R_PREDETECT;
    }
    goto R_Clean;
}

word cure_samar(void)
{
    word Offset = ((word*)(Buffer))[0], Offset2;

    Offset2 = (BU->Sub_Type == ST_COM) ? 0x23C8 : 0x20E7;

    if ( (Jump1[Offset+0x11] ^ Jump1[Offset+0x62]) == 0xFF)
        Xor_Byte(Buffer+Offset+Offset2,Buffer,Jump1[Offset+0x11],0x20);
    else
        Add_Byte(Buffer+Offset+Offset2,Buffer,(byte)(-Jump1[Offset+0x11]),0x20);

    if (BU->Sub_Type == ST_COM)
    {
        return Cure_COM_Imm(Buffer,4,BU->EP);
    }
    else
    {
        return Cure_EXE_Imm(Buffer,Buffer+2,NULL,NULL,BU->EP);
    }
}

word cure_samsec(void)
{
    return R_DELETE;
}
