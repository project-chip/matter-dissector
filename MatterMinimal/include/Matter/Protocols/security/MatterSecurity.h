/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERSECURITY_H_
#define MATTERSECURITY_H_

#include <Matter/Core/MatterVendorIdentifiers.hpp>

/**
 *   @namespace matter::Profiles::Security
 *
 *   @brief
 *     This namespace includes all interfaces within Matter for the
 *     Matter Security profile.
 */

namespace matter {
namespace Profiles {
namespace Security {

// Message Types for Matter Security Profile
//
enum
{
    // ---- PASE Protocol Messages ----
    kMsgType_PASEInitiatorStep1                 = 1,
    kMsgType_PASEResponderStep1                 = 2,
    kMsgType_PASEResponderStep2                 = 3,
    kMsgType_PASEInitiatorStep2                 = 4,
    kMsgType_PASEResponderKeyConfirm            = 5,
    kMsgType_PASEResponderReconfigure           = 6,

    // ---- CASE Protocol Messages ----
    kMsgType_CASEBeginSessionRequest            = 10,
    kMsgType_CASEBeginSessionResponse           = 11,
    kMsgType_CASEInitiatorKeyConfirm            = 12,
    kMsgType_CASEReconfigure                    = 13,

    // ---- Key Extraction Protocol ----
    kMsgType_KeyExportRequest                   = 30,
    kMsgType_KeyExportResponse                  = 31,
    kMsgType_KeyExportReconfigure               = 32,

    // ---- General Messages ----
    kMsgType_EndSession                         = 100,
    kMsgType_KeyError                           = 101,
    kMsgType_MsgCounterSyncResp                 = 102,
};


// Matter Security Status Codes
//
enum
{
    kStatusCode_SessionAborted                  = 1,  // The sender has aborted the session establishment process.
    kStatusCode_PASESupportsOnlyConfig1         = 2,  // PASE supports only Config1.
    kStatusCode_UnsupportedEncryptionType       = 3,  // The requested encryption type is not supported.
    kStatusCode_InvalidSessionId                    = 4,  // An invalid key id was requested.
    kStatusCode_DuplicateSessionId                  = 5,  // The specified key id is already in use.
    kStatusCode_KeyConfirmationFailed           = 6,  // The derived session keys do not agree.
    kStatusCode_InternalError                   = 7,  // The sender encountered an internal error (e.g. no memory, etc...).
    kStatusCode_AuthenticationFailed            = 8,  // The sender rejected the authentication attempt.
    kStatusCode_UnsupportedCASEConfiguration    = 9,  // No common CASE configuration supported.
    kStatusCode_UnsupportedCertificate          = 10, // An unsupported certificate was offered.
    kStatusCode_NoCommonPASEConfigurations      = 11, // No common PASE configuration supported.
    kStatusCode_KeyNotFound                     = 12, // The specified key is not found.
    kStatusCode_WrongEncryptionType             = 13, // The specified encryption type is invalid.
    kStatusCode_UnknownSessionType                  = 14, // The specified key has unknown key type.
    kStatusCode_InvalidUseOfSessionKey          = 15, // The specified key is used incorrectly.
    kStatusCode_InternalKeyError                = 16, // The receiver of the Matter message encountered key error.
    kStatusCode_NoCommonKeyExportConfiguration  = 17, // No common key export protocol configuration supported.
    kStatusCode_UnathorizedKeyExportRequest     = 18, // An unauthorized key export request.
};

// Matter Key Error Message Size
//
enum
{
    kMatterKeyErrorMessageSize                   = 9,  // The size of the key error message.
};

// Data Element Tags for the Matter Security Profile
//
enum
{
    // ---- Top-level Profile-Specific Tags ----
    kTag_MatterCertificate                       = 1,    // [ structure ] A Matter certificate.
    kTag_EllipticCurvePrivateKey                = 2,    // [ structure ] An elliptic curve private key.
    kTag_RSAPrivateKey                          = 3,    // [ structure ] An RSA private key.
    kTag_MatterCertificateList                   = 4,    // [ array ] An array of Matter certificates.
    kTag_MatterSignature                         = 5,    // [ structure ] A Matter signature object.
    kTag_MatterCertificateReference              = 6,    // [ structure ] A Matter certificate reference object.
    kTag_MatterCASECertificateInformation        = 7,    // [ structure ] A Matter CASE certificate information object.
    kTag_MatterCASESignature                     = 8,    // [ structure ] An Matter CASE signature object.
                                                        //    Presently this has the same internal structure as an ECDSASignature.
    kTag_MatterAccessToken                       = 9,    // [ structure ] A Matter Access Token object
    kTag_GroupKeySignature                      = 10,   // [ structure ] A Matter group Key signature object

    // ---- Context-specific Tags for MatterCertificate Structure ----
    kTag_SerialNumber                           = 1,    // [ byte string ] Certificate serial number, in BER integer encoding.
    kTag_SignatureAlgorithm                     = 2,    // [ unsigned int ] Enumerated value identifying the certificate signature algorithm.
    kTag_Issuer                                 = 3,    // [ path ] The issuer distinguished name of the certificate.
    kTag_NotBefore                              = 4,    // [ unsigned int ] Certificate validity period start (certificate date format).
    kTag_NotAfter                               = 5,    // [ unsigned int ] Certificate validity period end (certificate date format).
    kTag_Subject                                = 6,    // [ path ] The subject distinguished name of the certificate.
    kTag_PublicKeyAlgorithm                     = 7,    // [ unsigned int ] Identifies the algorithm with which the public key can be used.
    kTag_EllipticCurveIdentifier                = 8,    // [ unsigned int ] For EC certs, identifies the elliptic curve used.
    kTag_RSAPublicKey                           = 9,    // [ structure ] The RSA public key.
    kTag_EllipticCurvePublicKey                 = 10,   // [ byte string ] The elliptic curve public key, in X9.62 encoded format.
    kTag_RSASignature                           = 11,   // [ byte string ] The RSA signature for the certificate.
    kTag_ECDSASignature                         = 12,   // [ structure ] The ECDSA signature for the certificate.
    // Tags identifying certificate extensions (tag numbers 128 - 255)
    kCertificateExtensionTagsStart              = 128,
    kTag_AuthoritySessionIdentifier                 = 128,  // [ structure ] Information about the public key used to sign the certificate.
    kTag_SubjectSessionIdentifier                   = 129,  // [ structure ] Information about the certificate's public key.
    kTag_KeyUsage                               = 130,  // [ structure ] TODO: document me
    kTag_BasicConstraints                       = 131,  // [ structure ] TODO: document me
    kTag_ExtendedKeyUsage                       = 132,  // [ structure ] TODO: document me
    kCertificateExtensionTagsEnd                = 255,

    // ---- Context-specific Tags for RSAPublicKey Structure ----
    kTag_RSAPublicKey_Modulus                   = 1,    // [ byte string ] RSA public key modulus, in ASN.1 integer encoding.
    kTag_RSAPublicKey_PublicExponent            = 2,    // [ unsigned int ] RSA public key exponent.

    // ---- Context-specific Tags for ECDSASignature Structure ----
    kTag_ECDSASignature_r                       = 1,    // [ byte string ] ECDSA r value, in ASN.1 integer encoding.
    kTag_ECDSASignature_s                       = 2,    // [ byte string ] ECDSA s value, in ASN.1 integer encoding.

    // ---- Context-specific Tags for AuthoritySessionIdentifier Structure ----
    kTag_AuthoritySessionIdentifier_Critical        = 1,    // [ boolean ] True if the AuthoritySessionIdentifier extension is critical. Otherwise absent.
    kTag_AuthoritySessionIdentifier_SessionIdentifier   = 2,    // [ byte string ] TODO: document me
    kTag_AuthoritySessionIdentifier_Issuer          = 3,    // [ path ] TODO: document me
    kTag_AuthoritySessionIdentifier_SerialNumber    = 4,    // [ byte string ] TODO: document me

    // ---- Context-specific Tags for SubjectSessionIdentifier Structure ----
    kTag_SubjectSessionIdentifier_Critical          = 1,    // [ boolean ] True if the SubjectSessionIdentifier extension is critical. Otherwise absent.
    kTag_SubjectSessionIdentifier_SessionIdentifier     = 2,    // [ byte string ] Unique identifier for certificate's public key, per RFC5280.

    // ---- Context-specific Tags for KeyUsage Structure ----
    kTag_KeyUsage_Critical                      = 1,    // [ boolean ] True if the KeyUsage extension is critical. Otherwise absent.
    kTag_KeyUsage_KeyUsage                      = 2,    // [ unsigned int ] Integer containing key usage bits, per to RFC5280.

    // ---- Context-specific Tags for BasicConstraints Structure ----
    kTag_BasicConstraints_Critical              = 1,    // [ boolean ] True if the BasicConstraints extension is critical. Otherwise absent.
    kTag_BasicConstraints_IsCA                  = 2,    // [ boolean ] True if the certificate can be used to verify certificate signatures.
    kTag_BasicConstraints_PathLenConstraint     = 3,    // [ unsigned int ] Maximum number of subordinate intermediate certificates.

    // ---- Context-specific Tags for ExtendedKeyUsage Structure ----
    kTag_ExtendedKeyUsage_Critical              = 1,    // [ boolean ] True if the ExtendedKeyUsage extension is critical. Otherwise absent.
    kTag_ExtendedKeyUsage_KeyPurposes           = 2,    // [ array ] Array of enumerated values giving the purposes for which the public key can be used.

    // ---- Context-specific Tags for EllipticCurvePrivateKey Structure ----
    kTag_EllipticCurvePrivateKey_CurveIdentifier = 1,   // [ unsigned int ] MatterCurveId identifying the elliptic curve.
    kTag_EllipticCurvePrivateKey_PrivateKey     = 2,    // [ byte string ] Private key encoded using the I2OSP algorithm defined in RFC3447.
    kTag_EllipticCurvePrivateKey_PublicKey      = 3,    // [ byte string ] The elliptic curve public key, in X9.62 encoded format.

    // ---- Context-specific Tags for RSAPrivateKey Structure ----
    // ... TBD ...

    // ---- Context-specific Tags for MatterSignature Structure ----
    kTag_MatterSignature_ECDSASignature          = 1,    // [ structure ] ECDSA signature for the signed message.
    kTag_MatterSignature_RSASignature            = 2,    // [ byte string ] RSA signature for the signed message.
                                                        //   Per the schema, exactly one of ECDSASignature or RSASignature must be present.
    kTag_MatterSignature_SigningCertificateRef   = 3,    // [ structure ] A Matter certificate reference structure identifying the certificate
                                                        //   used to generate the signature. If absent, the signature was generated by the
                                                        //   first certificate in the RelatedCertificates list.
    kTag_MatterSignature_RelatedCertificates     = 4,    // [ array ] Array of certificates needed to validate the signature.  May be omitted if
                                                        //   validators are expected to have the necessary certificates for validation.
                                                        //   At least one of SigningCertificateRef or RelatedCertificates must be present.
    kTag_MatterSignature_SignatureAlgorithm      = 5,    // [ unsigned int ] Enumerated value identifying the signature algorithm.
                                                        //   Legal values per the schema are: kOID_SigAlgo_ECDSAWithSHA1, kOID_SigAlgo_ECDSAWithSHA256
                                                        //     and kOID_SigAlgo_SHA1WithRSAEncryption.
                                                        //   For backwards compatibility, this field should be omitted when the signature
                                                        //     algorithm is ECDSAWithSHA1.
                                                        //   When this field is included it must appear first within the MatterSignature structure.
                                                        //   kOID_SigAlgo_SHA1WithRSAEncryption is not presently supported in the code.

    // ---- Context-specific Tags for Matter Certificate Reference Structure ----
    kTag_MatterCertificateRef_Subject            = 1,    // [ path ] The subject DN of the referenced certificate.
    kTag_MatterCertificateRef_PublicSessionId        = 2,    // [ byte string ] Unique identifier for referenced certificate's public key, per RFC5280.

    // ---- Context-specific Tags for Matter CASE Certificate Information Structure ----
    kTag_CASECertificateInfo_EntityCertificate    = 1,  // [ structure ] A Matter certificate object representing the authenticating entity.
    kTag_CASECertificateInfo_EntityCertificateRef = 2,  // [ structure ] A Matter certificate reference object identifying the authenticating entity.
    kTag_CASECertificateInfo_RelatedCertificates  = 3,  // [ path ] A collection of certificates related to the authenticating entity.
    kTag_CASECertificateInfo_TrustAnchors         = 4,  // [ path ] A collection of Matter certificate reference identifying certificates trusted
                                                        //   by the authenticating entity.

    // ---- Context-specific Tags for Matter Access Token Structure ----
    kTag_AccessToken_Certificate                = 1,    // [ structure ] A Matter certificate object representing the entity that is trusted to
                                                        //   access a device or fabric.
    kTag_AccessToken_PrivateKey                 = 2,    // [ structure ] An EllipticCurvePrivateKey object containing the private key associated
                                                        //   with the access token certificate.
    kTag_AccessToken_RelatedCertificates        = 3,    // [ array, optional ] An optional array of certificates related to the access token
                                                        //   certificate that may be needed to validate it.

    kTag_GroupKeySignature_SignatureAlgorithm   = 1,    //  [ unsigned int ] Enumerated value identifying the certificate signature
                                                        //  algorithm.  Legal values are taken from the kOID_SigAlgo_* constant
                                                        //  namespace.  The only value currently supported is
                                                        //  kOID_SigAlgo_HMACWithSHA256.  When the tag is ommitted the signature
                                                        //  algorithm defaults to HMACWithSHA256
    kTag_GroupKeySignature_SessionId                = 2,    //  [ unsigned int ] Matter SessionId to be used to generate and verify the signature
    kTag_GroupKeySignature_Signature            = 3,    //  [ byte string ] Signature bytes themselves.


    // ---- Context-specific Tags for Matter representation of X.509 Distinguished Name Attributes ----
    //
    // The value used here must match *exactly* the OID enum values assigned to the corresponding object ids in the gen-oid-table.py script.
    //
    // WARNING! Assign no values higher than 127.
    //
    kTag_DNAttrType_CommonName                  = 1,    // [ UTF8 string ]
    kTag_DNAttrType_Surname                     = 2,    // [ UTF8 string ]
    kTag_DNAttrType_SerialNumber                = 3,    // [ UTF8 string ]
    kTag_DNAttrType_CountryName                 = 4,    // [ UTF8 string ]
    kTag_DNAttrType_LocalityName                = 5,    // [ UTF8 string ]
    kTag_DNAttrType_StateOrProvinceName         = 6,    // [ UTF8 string ]
    kTag_DNAttrType_OrganizationName            = 7,    // [ UTF8 string ]
    kTag_DNAttrType_OrganizationalUnitName      = 8,    // [ UTF8 string ]
    kTag_DNAttrType_Title                       = 9,    // [ UTF8 string ]
    kTag_DNAttrType_Name                        = 10,   // [ UTF8 string ]
    kTag_DNAttrType_GivenName                   = 11,   // [ UTF8 string ]
    kTag_DNAttrType_Initials                    = 12,   // [ UTF8 string ]
    kTag_DNAttrType_GenerationQualifier         = 13,   // [ UTF8 string ]
    kTag_DNAttrType_DNQualifier                 = 14,   // [ UTF8 string ]
    kTag_DNAttrType_Pseudonym                   = 15,   // [ UTF8 string ]
    kTag_DNAttrType_DomainComponent             = 16,   // [ UTF8 string ]
    kTag_DNAttrType_MatterDeviceId               = 17,   // [ unsigned int ]
    kTag_DNAttrType_MatterServiceEndpointId      = 18,   // [ unsigned int ]
    kTag_DNAttrType_MatterCAId                   = 19,   // [ unsigned int ]
    kTag_DNAttrType_MatterSoftwarePublisherId    = 20    // [ unsigned int ]
};

// Matter-defined elliptic curve ids
//
// NOTE: The bottom bits of each curve id must match the enum value used in the curve's
// ASN1 OID (see ASN1OID.h).
enum
{
    kMatterCurveId_NotSpecified                  = 0,

    kMatterCurveId_secp160r1                     = (kMatterVendor_NestLabs << 16) | 0x0021,
    kMatterCurveId_prime192v1                    = (kMatterVendor_NestLabs << 16) | 0x0015,
    kMatterCurveId_secp224r1                     = (kMatterVendor_NestLabs << 16) | 0x0025,
    kMatterCurveId_prime256v1                    = (kMatterVendor_NestLabs << 16) | 0x001B,

    kMatterCurveId_VendorMask                    = 0xFFFF0000,
    kMatterCurveId_VendorShift                   = 16,
    kMatterCurveId_CurveNumMask                  = 0xFF,
};


} // namespace Security
} // namespace Profiles
} // namespace matter

#endif /* MATTERSECURITY_H_ */
