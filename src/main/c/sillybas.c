/* Silly ANTIVIRUS Version 1.0 build 021                        */
/* Written by Valentin Kolesnikov, e-mail: javadev75@gmail.com  */

#include "sillyav.h"

word cure_vpp475(void);
word decode_vpp681(void);
word cure_vpp681(void);
word cure_bat(void);
word decode_samar(void);
word cure_samar(void);
word cure_samsec(void);
word decode_ssr(void);
word cure_ssr(void);
word decode_redar(void);
word cure_redar(void);
word decode_vcg(void);
word cure_vcg(void);
word cure_vpp1216(void);
word decode_vie(void);
word cure_vie(void);
word decode_acg(void);
word cure_acg(void);

#define FILE_REC_COUNT      11
#define MEM_REC_COUNT       2
#define SECTOR_REC_COUNT    1

// File records
FILE_RECORD Cur_Record[FILE_REC_COUNT] =
{
{
ST_COM | ST_EXE, 0l, 0, 0, 0l, 0, 0, 0l, "ACG-based", decode_acg, cure_acg
},
{ST_COM | ST_EXE,
0x20726F66l,
EOF_START+0x7A5, 0x10, 0x85F5A2B9l,
EOF_START+0x7A5, 0x40, 0x98BCE3A0l,
"BAT.102",
NULL, cure_bat
},
{
ST_COM, 0x214F3558l, 0, 7, 0x16A0A94Bl, 0, 0x46, 0x9375B4DCl, "EICAR test file", NULL, NULL
},
{
ST_COM | ST_EXE, 0l, 0, 0, 0l, 0, 0, 0l, "MME.SSR-based", decode_ssr, cure_ssr
},
{
ST_COM, 0l, 0, 0, 0l, BUFFER_START, 0x40, 0x2D4B59B7l, "RedArc.3529", decode_redar, cure_redar
},
{
ST_COM | ST_EXE, 0l, 0, 0, 0l, BUFFER_START+3, 0x40, 0x067EBB09l, "Samara.1536", decode_samar, cure_samar
},
{
ST_COM, 0l, 0, 0, 0l, 0, 0, 0l, "VCG-based", decode_vcg, cure_vcg
},
{
ST_COM, 0l, 0, 0, 0l, 0, 0, 0l, "Vienna-based", decode_vie, cure_vie
},
{
ST_COM,
0xFEB94EB4l,
EOF_START+0x639, 0x10, 0x31608535l,
EOF_START+0x6A3, 0x40, 0x5A069599l,
"VPP.475",
NULL, cure_vpp475
},
{
ST_COM,
0xF48B5655l,
EOF_START+0x557, 0x10, 0x140AADCCl,
BUFFER_START, 0x40, 0xCF527BE7l,
"VPP.681",
decode_vpp681,cure_vpp681
},
{
ST_COM,
0x0E061E60l,
EOF_START+0x343, 0x10, 0x031B39FF8l,
EOF_START+0x40C, 0x60, 0x4CC81D46l,
"VPP.1216",
NULL, cure_vpp1216
},
};

// Mem records
MEM_RECORD  Mem_Record[MEM_REC_COUNT] =
{
{
ST_MCB,
0xFC80609Cl, 0x109, 0, 0x10, 0xA1186A7Cl,
"Samara.1536",
NULL, NULL,
0x116,
{1,0xEB},
},
{
ST_CUT,
0x7701FA83l, 0x117, 0, 0x10, 0xF65AE0A3l,
"Samara.1536",
NULL, NULL,
0x11A,
{1,0xEB},
}
};

// Sector records
SECTOR_RECORD   Sec_Record[SECTOR_REC_COUNT] =
{
{
0x8EC02BFAl,
HEADER_START+0x20, 0x10, 0x05FE48BBl,
HEADER_START+0x20, 0x40, 0xF5EB6F2Al,
"Samara.1536",
NULL, cure_samsec
}
};

AV_FILE G_DATA =
{
    Cur_Record, FILE_REC_COUNT,
    Mem_Record, MEM_REC_COUNT,
    Sec_Record, SECTOR_REC_COUNT,
    FILE_REC_COUNT+MEM_REC_COUNT+SECTOR_REC_COUNT
};

AV_FILE *AV_F = &G_DATA;

