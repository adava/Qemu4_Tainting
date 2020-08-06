//
// Created by sina on 5/14/20.
//

#ifndef TAINT_UTILITY_H
#define TAINT_UTILITY_H

enum {
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2,
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14,
    R_R15 = 15,
    R_HIGH = 15,
    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 16, //from here, they are different than i386/cpu.h
    R_CH = 17,
    R_DH = 18,
    R_BH = 19,
    R_EXTRA = 20,
    R_EIP = 21,
    R_SEGS = 22,
    R_ES = 23,
    R_CS = 24,
    R_SS = 25,
    R_DS = 26,
    R_FS = 27,
    R_GS = 28,
    R_OTHERS
};

#endif //QEMU_UTILITY_H
