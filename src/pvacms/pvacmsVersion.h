/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVACMS_VERSION_H
#define PVACMS_VERSION_H

#include "pvacmsVersionNum.h"

#if PVACMS_MAJOR_VERSION<0
#  error Problem loading pvacmsVersionNum.h
#endif

#ifndef VERSION_INT
#  define VERSION_INT(V,R,M,P) ( ((V)<<24) | ((R)<<16) | ((M)<<8) | (P))
#endif

#define PVACMS_VERSION VERSION_INT(PVACMS_MAJOR_VERSION, PVACMS_MINOR_VERSION, PVACMS_MAINTENANCE_VERSION, 0)

#endif // PVACMS_VERSION_H
