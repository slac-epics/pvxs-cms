/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef TEST_CERT_PREFIX_H
#define TEST_CERT_PREFIX_H

// Deliberately non-default prefix (default is "CERT") so the tests exercise
// prefix-awareness rather than the hard-coded default.
static const char TEST_CERT_PV_PREFIX[] = "SPVA";

#endif // TEST_CERT_PREFIX_H
