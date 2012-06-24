/* Super ANTIVIRUS Version 1.0 build 021                        */
/* Written by Valentin Kolesnikov, e-mail: javadev75@gmail.com  */

#include "superav.h"

word cure_bat(void)
{
    return Ch_Size(BU->File_Length-102);
}

#define     MOV_BYTE    0x01
#define     CODE_0E     0x02
#define     CODE_1E     0x04
#define     CODE_68     0x08
#define     CODE_CB     0x10

#define Set_flag(x) { if (x == (flags+1)) flags |= x; }

word decode_ssr(void)
{
    word    ptr, ins_count, Save_ptr;
    byte    *pb = Buffer+0x2000, pref66, flags = 0;

    if (BU->Entry_Count > 0)
        goto R_Clean;
    if (BU->Tail < 18000 || BU->Tail > 22000)
        goto R_Clean;
    for (ins_count=0,ptr=0;ins_count<600;ins_count++)
    {
        pref66 = 0;
        Next_cmd:
        //DEBUG(("\n%04X->%02X %02X %02X %02X",ptr, pb[ptr], pb[ptr+1], pb[ptr+2], pb[ptr+3]));
        switch(pb[ptr++])
        {
            case 0x02: case 0x03: case 0x0A: case 0x0B:
            case 0x12: case 0x13: case 0x1A: case 0x1B: 
            case 0x22: case 0x23: case 0x2A: case 0x2B: 
            case 0x32: case 0x33: case 0x3A: case 0x3B:
            case 0xD0: case 0xD2:
                ptr += ( ((pb[ptr]&0xC0) == 0xC0) ? 0 : ((pb[ptr]&0xC0)>>6) )+1;
                break;
            case 0x80:
                ptr += ( ((pb[ptr]&0xC0) == 0xC0) ? 0 : ((pb[ptr]&0xC0)>>6) )+2;
                break;
            case 0x81:
                ptr += ( ((pb[ptr]&0xC0) == 0xC0) ? 0 : ((pb[ptr]&0xC0)>>6) )+ (pref66 ? 5 : 3);
                break;
            case 0xE8:
                Save_ptr = ptr+2;
                ptr += ((word*)(pb+ptr))[0]+2;
                break;
            case 0x26: case 0x27: case 0x2E: case 0x2F:
            case 0x36: case 0x37: case 0x3E: case 0x3F: case 0x90: case 0x99: 
            case 0xCC: case 0xFA: case 0xFB: case 0xFC: case 0xF5: case 0xF8: case 0xF9: case 0xF3: case 0x98:
            case 0xFD: 
                break;
            case 0xC3:
                ptr = Save_ptr;
                break;
            case 0xE4: case 0xCD:
                ptr++;
                break;
            case 0xEB:
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: 
                ptr += pb[ptr]+1;
                break;
            case 0x66:
                pref66 = 1;
                goto Next_cmd;
            case 0x0F:
                if (pb[ptr] == 0x33)
                {
                    Set_flag(CODE_68);
                    Set_flag(CODE_CB);
                    goto R_Predetect;
                }
                else
                    ptr += 2;
                break;
            case 0xC6:
                Set_flag(MOV_BYTE);
                ptr += 4;
                break;
            case 0x0E:
                Set_flag(CODE_0E);
                break;
            case 0x1E:
                Set_flag(CODE_1E);
                break;
            case 0x68:
                Set_flag(CODE_68);
                ptr += 2;
                break;
            case 0xCB:
                Set_flag(CODE_CB);
                goto R_Predetect;
            case 0x8E:
                Set_flag(MOV_BYTE);
                ptr++;
                break;
            case 0xC7:
                Set_flag(CODE_0E);
                ptr += 5;
                break;
            case 0x8C:
                Set_flag(CODE_1E);
                ptr++;
                break;
            default:
                goto R_Clean;
        }
        if (ptr > 0x2000) goto R_Clean;
    }
R_Clean:
    return R_CLEAN;
R_Predetect:
    if ( flags == 0x1F && ins_count > 200)
        return R_DETECT;
    goto R_Clean;
}

word cure_ssr(void)
{
    return R_DELETE;
}

#define F_INIT_DI   0x01
#define F_STOSW1    0x02
#define F_STOSW2    0x04
#define F_STOSW3    0x08
#define F_CD_21_1   0x10
#define F_JA_CHK    0x20
#define F_CD_21_2   0x40
#define F_CD_21_3   0x80
#define F_CD_21_4   0x100
#define F_CD_21_5   0x200
#define F_CD_21_6   0x400
#define F_PUSH_REG  0x800

#undef Set_flag
#define Set_flag(x) { if (x == (flags+1)) {flags |= x; break;} }

word decode_vcg(void)
{
    word ptr;
    word flags;
    
    if (BU->Entry_Count > 0)
        goto R_Clean;
    flags = 0;
    for (ptr=0;ptr<0x3E8;)
    {
        //DEBUG(("flags - %04X ptr - %04X->%02X %02X %02X %02X", flags, ptr,
        //  Jump1[ptr], Jump1[ptr+1], Jump1[ptr+2], Jump1[ptr+3] ));
        switch(Jump1[ptr++])
        {
            case 0x81:
                ptr += 3;
                break;
            case 0xBF:
                ptr += 2;
                Set_flag(F_INIT_DI);
                break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBD: case 0xBE:
                ptr += 2;
                break;
            case 0xAB:
                Set_flag(F_STOSW1);
                Set_flag(F_STOSW2);
                Set_flag(F_STOSW3);
                break;
            case 0x8B: case 0x87:
                ptr++;
                break;
            case 0x03: case 0x2B: case 0x33:
                ptr++;
                break;
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5D: case 0x5E: case 0x5F:
                Set_flag(F_PUSH_REG);
                // skip break
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x45: case 0x46: case 0x47: 
            case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4D: case 0x4E: case 0x4F:
            case 0x90:
                break;
            case 0xC3:
                if (flags == 0x0FFF && ptr > 0x2D0)
                    return R_DETECT;
                break;
            case 0xCD:
                if (Jump1[ptr++] == 0x21)
                {
                    Set_flag(F_CD_21_1);
                    Set_flag(F_CD_21_2);
                    Set_flag(F_CD_21_3);
                    Set_flag(F_CD_21_4);
                    Set_flag(F_CD_21_5);
                    Set_flag(F_CD_21_6);
                }
                break;
            case 0x73:
                if (Jump1[ptr++] < 0x70)
                    Set_flag(F_JA_CHK);
                break;
            default:
                goto R_Clean;           
        }
    }
R_Clean:
    return R_CLEAN;
}

word cure_vcg(void)
{
    return R_DELETE;
}

#define     Mov_si_bytes    0x0001
#define     Mov_di_100      0x0002
#define     Mov_cx_3        0x0002
#define     Rep_movsb       0x0004
#define     Mov_ah_1A       0x0008
#define     Mov_es_2C       0x0010
#define     Loop_fa         0x0020
#define     Mov_ah_4E       0x0040
#define     Mov_ax_3D02     0x0080
#define     Mov_ah_3F       0x0100
#define     Mov_ax_4202     0x0200
#define     Mov_ah_40_1     0x0400
#define     Mov_ax_4200     0x0800
#define     Mov_ah_40_2     0x1000
#define     Mov_ah_3E       0x2000

#define     SourceOff       WC(0)

word decode_vie(void)
{
register WORD ptr;
register WORD flags;
    WORD Save_ptr, Ins_count;

    flags = 0; SourceOff = Save_ptr = 0xFFFF;

    for (ptr=0, Ins_count=0; ptr<JUMP1_SIZE-6;Ins_count++) 
    {
        //DEBUG(("ptr - %04X -> %02X %02X", ptr, BA(ptr), BA(ptr+1)));
        switch(BA(ptr++))
        {
            case 0xBA:  case 0xBB:
                if (Save_ptr == 0xFFFF && SourceOff == 0xFFFF)
                    SourceOff = WA(ptr);
                ptr += 2;
                break;
            case 0xBE:
                SetFlag(Mov_si_bytes);
                if (flags == Mov_si_bytes)
                {
                    //DEBUG(("Offset - %04X",WA(ptr)));
                    SourceOff = WA(ptr);
                }
                ptr += 2;
                break;
            case 0xBF:
                if (WA(ptr) == 0x100)
                    SetFlag(Mov_di_100);
                ptr += 2;
                break;
            case 0xB4:
                switch (BA(ptr))
                {
                    case 0x1A:
                        SetFlag(Mov_ah_1A);
                        break;
                    case 0x4E:
                        SetFlag(Mov_ah_4E);
                        break;
                    case 0x3F:
                        SetFlag(Mov_ah_3F);
                        break;
                    case 0x40:
                        SetFlag(Mov_ah_40_2);
                        SetFlag(Mov_ah_40_1);
                        break;
                    case 0x3E:
                        SetFlag(Mov_ah_3E);
                        break;
                }
                ptr++;
                break;
            case 0xB8: 
                switch (WA(ptr))
                {
                    case 0x3D02:
                        SetFlag(Mov_ax_3D02);
                        break;
                    case 0x4200:
                        SetFlag(Mov_ax_4200);
                        break;
                    case 0x4202:
                        SetFlag(Mov_ax_4202);
                        break;
                }
                // skip break;
            case 0x05: 
            case 0x25: case 0x2D: 
            case 0x3D: case 0xBC: case 0xBD:
            case 0xA0: case 0xA2:
                ptr += 2;
                break;
            case 0xE2: 
                if ( BA(ptr) == 0xF8 || BA(ptr) == 0xFA ||  BA(ptr) == 0xFB )
                    SetFlag(Loop_fa);
                ptr++;
                break;
            case 0x06: case 0x07: case 0x0E: case 0x1E: case 0x1F: 
            case 0x26: case 0x2E: case 0x3E: case 0x90:
            case 0x40: case 0x47: case 0x4B:
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x55: case 0x56: case 0x57: 
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5D: case 0x5E: case 0x5F: 
            case 0x60: case 0x61: case 0x9D:
            case 0xA6: case 0xAA: case 0xAC: case 0xAE: case 0xF9: case 0xFB: case 0xFC:
                break;
            case 0xB9:
                switch (WA(ptr))
                {
                    case 3:
                        SetFlag(Mov_cx_3);
                        break;
                    case 0x4202:
                        SetFlag(Mov_ax_4202);
                        break;
                }
                ptr += 2;
                break;
            case 0xF2:
                ptr ++;
                break;
            case 0xA4:
                if ( BA(ptr) == 0xA5)
                    SetFlag(Rep_movsb);
                break;
            case 0xA5:  // A5 A4
            case 0xF3:
                if ( BA(ptr) == 0xA4 || BA(ptr) == 0x90)
                    SetFlag(Rep_movsb);
                break;
            case 0xB1: case 0xB2: case 0xB3: case 0xB5: case 0xB6: case 0xB7: case 0xCD:
            case 0x24: case 0x2C: case 0x3C:
            case 0x72: case 0x75: case 0x77: case 0x7C: case 0xE4:
                ptr++;
                break;
            case 0x73: case 0x74: case 0x7D: 
            case 0x7F: case 0xEB:
                ptr += (BA(ptr) > 0x30 ? 0 : BA(ptr) )+1;
                break;
            case 0xE8: 
                if (Save_ptr == 0xFFFF)
                    Save_ptr = ptr+2;
                // skip break
                ptr += (WA(ptr) > 0x200 ? 0 : WA(ptr) )+2;
                break;
            case 0xE9: 
                ptr += (WA(ptr) > 0x50 ? 0 : WA(ptr) )+2;
                break;
            case 0xB0: case 0xE6: case 0xCC:
                ptr++;
                break;
            case 0x89:
                if (BA(ptr) == 0xD6)
                    SetFlag(Mov_si_bytes);
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+1;
                break;
            case 0x8B:
                if (BA(ptr) == 0xF2)
                    SetFlag(Mov_si_bytes);
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+1;
                break;
            case 0x8D:
                if ( BA(ptr) == 0x16 && flags < Rep_movsb )
                    SourceOff = WA(ptr+1);
                if ( (BA(ptr) == 0x77 || BA(ptr) == 0xB7) && flags < Rep_movsb )
                {
                    SetFlag(Mov_si_bytes);
                    SourceOff += BA(ptr+1);
                }
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+1;
                break;
            case 0x8E:
                if ( (BA(ptr) == 6 && WA(ptr+1) == 0x2C) || BA(ptr) == 5)
                    SetFlag(Mov_es_2C);
                // skip break;
            case 0x01: case 0x02: case 0x03: case 0x0A: case 0x0B: case 0x0C:
            case 0x12: case 0x13: case 0x1A: case 0x1B: 
            case 0x22: case 0x23: case 0x29: case 0x2A: case 0x2B: 
            case 0x31: case 0x32: case 0x33: case 0x34: case 0x38: case 0x3A: case 0x3B:
            case 0x88: case 0x8A: case 0x8C:
            case 0xC5: 
            case 0xD1: case 0xD3: 
            case 0xFE:
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+1;
                break;
            case 0x83:
                if ( BA(ptr) == 0xC6 && flags < Rep_movsb )
                    SourceOff += BA(ptr+1);
            case 0x80: case 0xC6:
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+2;
                break;
            case 0x81: case 0xC7:
                if ( BA(ptr) == 0xC6 && flags < Rep_movsb )
                    SourceOff += WA(ptr+1);
                ptr += ( ((BA(ptr)&0xC0) == 0xC0) ? 0  : ( ((BA(ptr)&7) == 6) ? 2  : ((BA(ptr)&0xC0)>>6) ) )+3;
                break;
            case 0xC3:
                if (Save_ptr != 0xFFFF)
                {   
                    ptr = Save_ptr;
                    Save_ptr = 0xFFFF;
                }
                break;
            default: case 0xC2: 
                goto R_Predetect;
        }
    }
    R_Clean:
        return R_CLEAN;
    R_Predetect:
        //DEBUG(("Ins_count - %04X", Ins_count));
        //DEBUG(("SourceOff - %04X", SourceOff));
        if (Ins_count > 85 && flags == 0x3FFF)
            return R_DETECT;
        goto R_Clean;
}

word cure_vie(void)
{
    SourceOff -= 0x100;
    if (SourceOff > BU->File_Length)
        return R_FAIL;
    if (BU->EP > 0x90 && SourceOff < BU->EP-0x90)
        return R_FAIL;
    Seek_Read(SourceOff,Buffer,3);
    Seek_Write(0,Buffer,3);
    return Ch_Size(BU->EP);
}


#define     CD1A            0x0001
#define     Find_first      0x0002
#define     Open_write      0x0004
#define     Read_3          0x0008
#define     Seek_end        0x0010
#define     Close_f         0x0020
#define     Find_next       0x0040
#define     Jmp_100         0x0080

#define     Call4B00        0x0001
#define     Sub600          0x0002
#define     MovZ            0x0004
#define     Read21          0x0008
#define     Write21hi       0x0010
#define     Write21lo       0x0020
#define     CmpA000         0x0040
#define     CodeRetf        0x0080

#define     SourceOff       WC(0)

#define STACK_LIM   10

#define StackW(x)   HEU->em_stack[x]
#define Tmp_Data    HEU->tmp_data
#define Em_Flags    HEU->em_flags

#define RegsB(a)    HEU->regs[(a) & 3].c[(a)>>2]
#define RegsW(x)    HEU->regs[x].w
#define Write_Addr  HEU->write_addr
#define Write_Data  HEU->write_data
#define Calc_incsp  HEU->calc_incsp
#define Base_ip     HEU->base_ip
#define Em_sp       HEU->em_sp

#define ax HEU->regs[0].w
#define cx HEU->regs[1].w
#define dx HEU->regs[2].w
#define bx HEU->regs[3].w

#define al HEU->regs[0].b.l
#define ah HEU->regs[0].b.h
#define cl HEU->regs[1].b.l

#define PushW(word1) {      \
    DEBUG(("Push word %04X",word1));    \
    StackW(Em_sp) = word1;  \
    if (Em_sp < STACK_LIM) { Em_sp += pref66 ? 2 : 1; }         \
    }
#define PopW(word1) {       \
    if (Em_sp == 0) word1 = StackW(0);  \
    else { Em_sp -= pref66 ? 2 : 1; word1 = StackW(Em_sp); }    \
    DEBUG(("Pop word %04X",word1)); \
    }

typedef union
{
    WORD  w;
    BYTE  c[2];
    struct {
      BYTE  l;
      BYTE  h;
    } b;
} REGS;

typedef struct
{
    byte    buffer[0x100];
    REGS    regs[8];
    word    em_flags;
    word    tmp_data;
    word    write_addr;
    word    write_data;
    word    em_sp;
    dword   base_ip;
    word    calc_incsp;
    word    em_stack[STACK_LIM];
} ACG_DATA;

#define HEU ((ACG_DATA*)Buffer)

static void Read_Word(word ptr)
{
    dword   Offset;
    Offset = WC(ptr+1)+Base_ip;
    if (Offset < BU->File_Length)
    {
        Seek_Read(Offset,&Tmp_Data,2);
    }
    DEBUG(("Read ->%04X: %04X",ptr, Tmp_Data));
}

static void Write_Word(word ptr, word Data)
{
    Write_Addr = WC(ptr+1);
    Write_Data = Data;
}

word decode_acg(void)
{
    byte d0;
    word ptr;
    word flags;
    word Ins_count;
    byte pref66;
    dword Base_Addr;
    flags = 0;

    if (BU->Entry_Count > 0)
        goto R_Clean;
    Fill_Data(HEU, 0, sizeof(ACG_DATA));
    if (BU->Sub_Type == ST_COM)
        Base_ip = (DWORD)(-0x100);
    else
        Base_ip = (DWORD)(HeaderExe->CS+HeaderExe->HdrSize)*0x10;
    DEBUG(("Base ip - %04X", Base_ip));
    Calc_incsp = 1;
    Em_sp = ptr = Ins_count= 0;
    Base_Addr = BU->EP;
    Next_Block:
    Base_Addr += (signed short)ptr;
    if ( Base_Addr >= BU->File_Length)
        goto R_Predetect;
    Seek_Read(Base_Addr,HEU->buffer,0x100);
    for (ptr = 0;ptr<0x100-6;Ins_count++)
    {
        if (Ins_count > 800)
            goto R_Predetect;
        DEBUG(("ptr - %08lX -> %02X %02X", Base_Addr+ptr, BC(ptr), BC(ptr+1)));
        //DEBUG(("Stack - %04X %04X  %04X", StackW(0), StackW(1), StackW(2)));
        //DEBUG(("Stack - %04d ",Em_sp));
        DEBUG(("Regs - %04X %04X %04X %04X - %04X %04X %04X %04X - %04X",RegsW(0),RegsW(1),RegsW(2),RegsW(3),RegsW(4),RegsW(5),RegsW(6),RegsW(7),Em_Flags));
        pref66 = 0;
        Next_cmd:
        d0 = BC(ptr++);
        switch(d0)
        {
            case 0x0F:
                switch(BC(ptr++))
                {
                    case 0x82:
                        if (Em_Flags & 0x0001)
                            goto JmpJcc1;
                            ptr+=2;
                            break;           // JC
                    case 0x83:
                        if (!(Em_Flags & 0x0001))
                            goto JmpJcc1;
                            ptr+=2;
                            break;          // JNC
                    case 0x84:  case 0x85:  case 0x87:
                    JmpJcc1:
                        ptr += (signed short)WC(ptr)+2;
                        break;
                    case 0x90:  case 0x91:  case 0x92:  case 0x93:  case 0x94:  case 0x95:  case 0x96:  case 0x97:  
                    case 0x98:  case 0x99:  case 0x9A:  case 0x9B:  case 0x9C:  case 0x9D:  case 0x9E:  case 0x9F:
                        ptr++;
                        break;
                    case 0xA0:  case 0xA8:
                        PushW(Tmp_Data);
                        break;
                    case 0xA1:  case 0xA9:
                        PopW(Tmp_Data);
                        break;
                    case 0xB0:  case 0xB1:  case 0xB2:  case 0xB3:  case 0xB4:  case 0xB5:  case 0xB6:  case 0xB7:  
                    case 0xB8:  case 0xB9:  case 0xBA:  case 0xBB:  case 0xBC:  case 0xBD:  case 0xBE:  case 0xBF:
                        ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+1;
                        break;
                    default:
                        goto R_Predetect;
                }
                break;
            case 0x06:  case 0x0E:  case 0x16:  case 0x1E:  case 0x9C:
                PushW(Tmp_Data);
                break;
            case 0x07:  case 0x1F:  
                PopW(Tmp_Data);
                break;
            case 0x86:  
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    Tmp_Data = RegsB((BC(ptr)&0x38)>>3);
                    RegsB((BC(ptr)&0x38)>>3) = RegsB(BC(ptr)&0x7);  
                    RegsB(BC(ptr)&0x7) = (byte)Tmp_Data;
                }
            Default_ptr_pl:
                ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+1;
                break;
            case 0x87:  
                if ((BC(ptr)&0xC7)==6)
                {
                    if (WC(ptr+1) == Write_Addr)
                    {
                        Tmp_Data = Write_Data;
                    }
                    else
                    {
                        Read_Word(ptr);
                    }
                    Write_Word(ptr,RegsW((BC(ptr)&0x38)>>3) );
                    RegsW( (BC(ptr)&0x38)>>3 ) = Tmp_Data;
                }
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    Tmp_Data = RegsW((BC(ptr)&0x38)>>3);
                    RegsW((BC(ptr)&0x38)>>3) = RegsW(BC(ptr)&0x7);  
                    RegsW(BC(ptr)&0x7) = Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x88:  
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    RegsB(BC(ptr)&0x7) = RegsB( (BC(ptr)&0x38)>>3 );
                }
                goto Default_ptr_pl;
            case 0x89:  
                if ((BC(ptr)&0xC7)==6)
                {
                    DEBUG(("Write 89 %04X",WC(ptr+1)));
                    if (WC(ptr+1)==0x86)
                    {
                        SetFlag(Write21hi);
                    }
                }
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    RegsW(BC(ptr)&0x7) = RegsW( (BC(ptr)&0x38)>>3 );
                }
                goto Default_ptr_pl;
            case 0x8A:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) = (byte)Tmp_Data;
                }
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    RegsB( (BC(ptr)&0x38)>>3 ) = RegsB(BC(ptr)&0x7);
                }
                goto Default_ptr_pl;
            case 0x8B:  
                if ((BC(ptr)&0xC7)==6)
                {
                    if (WC(ptr+1)==0x84 && pref66)
                    {
                        SetFlag(Read21);
                    }
                    Read_Word(ptr);
                    RegsW( (BC(ptr)&0x38)>>3 ) = Tmp_Data;
                }
                if ((BC(ptr)&0xC0)==0xC0)
                {
                    RegsW( (BC(ptr)&0x38)>>3 ) = RegsW(BC(ptr)&0x7);
                }
                goto Default_ptr_pl;
            case 0x02:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) += Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x03:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsW( (BC(ptr)&0x38)>>3 ) += Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x0A:
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) |= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x0B:
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsW( (BC(ptr)&0x38)>>3 ) |= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x22:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) &= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x23:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsW( (BC(ptr)&0x38)>>3 ) &= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x2A:
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) -= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x2B:
                if ( (BC(ptr)&0xC0)==0xC0 )
                {
                    if ( ((BC(ptr)&0x38)>>3) == (BC(ptr)&0x7) )
                        RegsW( BC(ptr)&0x7 ) = 0;
                }
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    if ( Tmp_Data == 0x600)
                    {
                        SetFlag(Sub600);
                        Em_Flags &= 0xFFFE;
                        DEBUG(("Clear flag"));
                    }
                    RegsW( (BC(ptr)&0x38)>>3 ) -= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x32:  
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsB( (BC(ptr)&0x38)>>3 ) ^= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x33:
                if ( (BC(ptr)&0xC0)==0xC0 )
                {
                    if ( ((BC(ptr)&0x38)>>3) == (BC(ptr)&0x7) )
                        RegsW( BC(ptr)&0x7 ) = 0;
                }
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    RegsW( (BC(ptr)&0x38)>>3 ) ^= Tmp_Data;
                }
                goto Default_ptr_pl;
            case 0x8F:
                PopW(Tmp_Data);
                // Skip break;
            case 0x00:  case 0x01:  case 0x08:  case 0x09:  
            case 0x10:  case 0x11:  case 0x12:  case 0x13:  case 0x18:  case 0x19:  case 0x1A:  case 0x1B:
            case 0x20:  case 0x21:  case 0x28:  case 0x29:  
            case 0x30:  case 0x31:  case 0x38:  case 0x39:  case 0x3A:
            case 0x84:  case 0x85:  case 0x8C:  case 0x8E:
            case 0xD0:  case 0xD1:  case 0xD2:  case 0xD3:
                goto Default_ptr_pl;
            case 0x3B:
                if ((BC(ptr)&0xC7)==6)
                {
                    Read_Word(ptr);
                    if (Tmp_Data == 0xA000 && pref66)
                        SetFlag(CmpA000);
                }
                goto Default_ptr_pl;
            case 0x8D:  
                switch ( (BC(ptr)&0xC7) )
                {
                    case 0x4:
                        RegsW((BC(ptr)&0x38)>>3) = RegsW(6);
                        break;  
                    case 0x5:
                        RegsW((BC(ptr)&0x38)>>3) = RegsW(7);
                        break;  
                    case 6:
                        RegsW((BC(ptr)&0x38)>>3) = WC(ptr+1);
                        break;  
                    case 0x7:
                        RegsW((BC(ptr)&0x38)>>3) = RegsW(3);
                        break;  
                    case 0x46:
                        RegsW((BC(ptr)&0x38)>>3) = RegsW(5);
                        break;  
                }
                goto Default_ptr_pl;
            case 0x83:
                if (BC(ptr)==0xC4)
                {
                    pref66 = 0;
                    switch(BC(ptr+1))
                    {
                        case 0x4:
                            PopW(Tmp_Data);
                            // skip break
                        case 0x2:
                            PopW(Tmp_Data);
                            break;
                    }
                }
                if ( (BC(ptr)&0xC0) == 0xC0 )
                {
                    switch (BC(ptr)&0x38)
                    {
                        case 0x0:
                            RegsW( BC(ptr)&7 ) += BC(ptr+1);
                            break;
                        case 0x8:
                            RegsW( BC(ptr)&7 ) |= BC(ptr+1);
                            break;
                        case 0x20:
                            RegsW( BC(ptr)&7 ) &= BC(ptr+1);
                            break;
                        case 0x28:
                            RegsW( BC(ptr)&7 ) -= BC(ptr+1);
                            break;
                        case 0x30:
                            RegsW( BC(ptr)&7 ) ^= BC(ptr+1);
                            break;
                    }
                }
                // skip break
            case 0xC0:  case 0xC1:  
            Default_ptr_pl_1:
                ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+2;
                break;
            case 0xC6:
                if (BC(ptr+1) == 0x5A)
                    SetFlag(MovZ);
                goto Default_ptr_pl_1;
            case 0x80: 
                if ( (BC(ptr)&0xC0) == 0xC0 )
                {
                    switch (BC(ptr)&0x38)
                    {
                        case 0x0:
                            RegsB( BC(ptr)&7 ) += BC(ptr+1);
                            break;
                        case 0x8:
                            RegsB( BC(ptr)&7 ) |= BC(ptr+1);
                            break;
                        case 0x20:
                            RegsB( BC(ptr)&7 ) &= BC(ptr+1);
                            break;
                        case 0x28:
                            RegsB( BC(ptr)&7 ) -= BC(ptr+1);
                            break;
                        case 0x30:
                            RegsB( BC(ptr)&7 ) ^= BC(ptr+1);
                            break;
                    }
                }
                goto Default_ptr_pl_1;
                //ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+2;
                //break;
            case 0x81:
                if ( (BC(ptr)&0xC0) == 0xC0 )
                {
                    switch (BC(ptr)&0x38)
                    {
                        case 0x0:
                            RegsW( BC(ptr)&7 ) += WC(ptr+1);
                            break;
                        case 0x8:
                            RegsW( BC(ptr)&7 ) |= WC(ptr+1);
                            break;
                        case 0x20:
                            RegsW( BC(ptr)&7 ) &= WC(ptr+1);
                            break;
                        case 0x28:
                            if ( WC(ptr+1) == 0x600)
                            {
                                SetFlag(Sub600);
                                Em_Flags &= 0xFFFE;
                                DEBUG(("Clear flag"));
                            }
                            RegsW( BC(ptr)&7 ) -= WC(ptr+1);
                            break;
                        case 0x30:
                            RegsW( BC(ptr)&7 ) ^= WC(ptr+1);
                            break;
                        case 0x38:
                            if (WC(ptr+1) == 0xA000 && pref66)
                                SetFlag(CmpA000);
                            break;
                    }
                }
                ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+(pref66 ? 5 : 3);
                break;
                // skip break;
            case 0xC7:
                if ((BC(ptr)&0xC7)==6)
                {
                    if (WC(ptr+1)==0x84)
                    {
                        SetFlag(Write21lo);
                    }
                }
                if ( (BC(ptr)&0xC0) == 0xC0 )
                {
                    RegsW( BC(ptr)&7 ) = WC(ptr+1);
                }
                ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+(pref66 ? 5 : 3);
                break;
            case 0xF6:
                switch(BC(ptr)&0x38)
                {
                    case 0x00:
                        ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+2;
                        break;
                    case 0x10:  case 0x18:  case 0x20:  case 0x28:  
                        goto Default_ptr_pl;
                    default:
                        goto R_Predetect;

                }
                break;
            case 0xF7:
                switch(BC(ptr)&0x38)
                {
                    case 0:
                        ptr += ( ((BC(ptr)&0xC0) == 0xC0) ? 0  : ( ((BC(ptr)&0xC7) == 6) ? 2  : ((BC(ptr)&0xC0)>>6) ) )+(pref66 ? 5 : 3);
                        break;
                    case 0x10:  case 0x18:  case 0x20:  case 0x28:
                        goto Default_ptr_pl;
                    default:
                        goto R_Predetect;

                }
                break;
            case 0xFE:  case 0xFF:
                switch(BC(ptr)&0x38)
                {
                    case 0x30:
                        PushW(Tmp_Data);
                        // skip break;
                    case 0x00:  case 0x08:
                        goto Default_ptr_pl;
                    case 0x20:
                        ptr = RegsW(BC(ptr)&7);
                        ptr -= (word)(Base_Addr+0x100);
                        break;
                    default:
                        goto R_Predetect;

                }
                break;
            case 0x44:
                if (Calc_incsp-- == 0)
                {
                    pref66 = 0;
                    PopW(Tmp_Data);
                    Calc_incsp = 1;
                }
                // skip break;
            case 0x27:  case 0x2F:
            case 0x26:  case 0x2E:  case 0x36:  case 0x37:  case 0x3E:  case 0x3F:  case 0x64:  case 0x65:
            case 0x40:  case 0x41:  case 0x42:  case 0x43:  case 0x45:  case 0x46:  case 0x47:  
            case 0x48:  case 0x49:  case 0x4A:  case 0x4B:  case 0x4D:  case 0x4E:  case 0x4F:
            case 0x98:  case 0x99:  case 0x90:  
            case 0x9B:  case 0x9E:  case 0x9F:  case 0x60:
            case 0xA6:  case 0xAC:  case 0xAE:
            case 0xF5:  case 0xF8:  case 0xF9:  case 0xD6:  case 0xD7:
                break;
            case 0x91:  case 0x92:  case 0x93:  case 0x95:  case 0x96:  case 0x97:
                Tmp_Data = RegsW(d0&7);
                RegsW(d0&7) = RegsW(0); 
                RegsW(0) = Tmp_Data;
                break;
            case 0x50:  case 0x51:  case 0x52:  case 0x53:  case 0x54:  case 0x55:  case 0x56:  case 0x57:
                PushW(RegsW(d0&7));
                break;
            case 0x58:  case 0x59:  case 0x5A:  case 0x5B:  case 0x5D:  case 0x5E:  case 0x5F:
                PopW(RegsW(d0&7));
                break;
            case 0x66:
                pref66 = 1;
                goto Next_cmd;
            case 0x14:  case 0x1C:  case 0x3C:
            case 0xA8:
            case 0xD4:  case 0xD5:
            case 0xE4:  case 0xE5:
                ptr++;
                break;
            case 0xB0:  case 0xB1:  case 0xB2:  case 0xB3:  case 0xB4:  case 0xB5:  case 0xB6:  case 0xB7:
                RegsB(d0&7) = BC(ptr);
                ptr++;
                break;
            case 0xCD:  
                if (BC(ptr) == 0x1A)
                    SetFlag(CD1A);
                if (BC(ptr) == 0x21)
                {
                    switch(ah)
                    {
                        case 0x4B:
                            if (dx == 0x6721)
                                SetFlag(Call4B00);
                            Em_Flags |= 1;
                            break;
                        case 0x4E:
                            SetFlag(Find_first);
                            Em_Flags &= 0xFFFE;
                            break;
                        case 0x3D:
                            if (al == 2)
                                SetFlag(Open_write);
                            Em_Flags &= 0xFFFE;
                            break;
                        case 0x3F:
                            if (cl == 3)
                                SetFlag(Read_3);
                            Em_Flags &= 0xFFFE;
                            break;
                        case 0x42:
                            if (al == 2)
                                SetFlag(Seek_end);
                            Em_Flags &= 0xFFFE;
                            break;
                        case 0x3E:
                            SetFlag(Close_f);
                            Em_Flags &= 0xFFFE;
                            break;
                        case 0x4F:
                            SetFlag(Find_next);
                            Em_Flags |= 1;
                            break;
                    }                   
                }
                DEBUG(("CALL INT !!! "));
                ptr++;
                break;
            case 0xA0:  
                Read_Word((WORD)(ptr-1));
                al = (byte)Tmp_Data;
                ptr += 2;
                break;
            case 0xA1:  
                if (WC(ptr)==0x84 && pref66)
                {
                    SetFlag(Read21);
                }
                Read_Word((WORD)(ptr-1));
                RegsW( 0 ) = Tmp_Data;
                ptr += 2;
                break;
            case 0xA3:
                if (WC(ptr)==0x86)
                {
                    SetFlag(Write21hi);
                }
                // skip break;
            case 0xA2:  
                ptr += 2;
                break;
            case 0x72:
                if (Em_Flags & 0x0001)
                    goto JmpJcc;
                    ptr++;
                    break;           // JC
            case 0x73:
                if (!(Em_Flags & 0x0001))
                    goto JmpJcc;
                    ptr++;
                    break;          // JNC
            case 0x70:  case 0x71:  case 0x74:  case 0x75:  case 0x76:  case 0x77:  
            case 0x78:  case 0x79:  case 0x7A:  case 0x7B:  case 0x7C:  case 0x7D:  case 0x7E:  case 0x7F:
            case 0xE0:  case 0xE1:  case 0xE2:  case 0xE3:
            case 0xEB:
            JmpJcc:
                ptr += (signed char)BC(ptr)+1;
                break;
            case 0xE8:
                PushW((word)(Base_Addr+ptr+0x102));
                ptr += WC(ptr)+(pref66 ? 4 : 2);
                break;
            case 0xC2:
                if (BC(ptr)==4)
                {
                    PopW(ptr);
                    PopW(Tmp_Data);
                }
                else
                {
                    PopW(ptr);
                }
                PopW(Tmp_Data);
                if (ptr == 0x100)
                {
                    SetFlag(Jmp_100);
                    goto R_Predetect;
                }
                ptr -= (word)(Base_Addr+0x100);
                break;
            case 0xC3:
                PopW(ptr);
                if (ptr == 0x100)
                {
                    SetFlag(Jmp_100);
                    goto R_Predetect;
                }
                ptr -= (word)(Base_Addr+0x100);
                break;
            case 0xCB:
                SetFlag(CodeRetf);
                goto R_Predetect;
            case 0x04:  
                al += BC(ptr);
                ptr++;
                break;
            case 0x05:  
                RegsW(0) += WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0x0C:  
                al |= BC(ptr);
                ptr++;
                break;
            case 0x0D:  
                RegsW(0) |= WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0x24:  
                al &= BC(ptr);
                ptr++;
                break;
            case 0x25:  
                RegsW(0) &= WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0x2C:  
                al -= BC(ptr);
                ptr++;
                break;
            case 0x2D:  
                if (WC(ptr)==0x600)
                {
                    SetFlag(Sub600);
                    Em_Flags &= 0xFFFE;
                }
                RegsW(0) -= WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0x34:  
                al ^= BC(ptr);
                ptr++;
                break;
            case 0x35:  
                RegsW(0) ^= WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0x3D:
                if (WC(ptr) == 0xA000 && pref66)
                    SetFlag(CmpA000);
                // skip break
            case 0x15:  case 0x1D:
            case 0xA9:
                ptr += (pref66 ? 4 : 2);
                break;
            case 0xB8:  case 0xB9:  case 0xBA:  case 0xBB:   case 0xBD: case 0xBE:  case 0xBF:
                RegsW(d0&7) = WC(ptr);
                ptr += (pref66 ? 4 : 2);
                break;
            case 0xE9: 
                ptr += WC(ptr)+(pref66 ? 4 : 2);
                break;
            default:
                goto R_Predetect;
        }
    }
    goto Next_Block;
    R_Predetect:
        DEBUG(("Ins_count - %04d", Ins_count));
        DEBUG(("Flags     - %04X", flags));
        if (Ins_count > 60 && flags == 0xFF)
            return R_DETECT;
    R_Clean:
        return R_CLEAN;
}

WORD cure_acg(void)
{
    DEBUG(("SP (%d)-> %04X, %04X", Em_sp, StackW(0), StackW(1) ));
    if (Em_sp == 2 && StackW(0) == 0 && (StackW(1) == 0x100 || StackW(1) == 0) )
    {
        return CutPast_File(0, 0x20, (word)BU->Tail);
    }
    return R_FAIL;
}
