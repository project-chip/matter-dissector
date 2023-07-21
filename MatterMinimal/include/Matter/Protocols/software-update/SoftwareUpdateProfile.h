/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SW_UPDATE_PROFILE_H
#define _SW_UPDATE_PROFILE_H

/**
 *   @namespace matter::Profiles::SoftwareUpdate
 *
 *   @brief
 *     This namespace includes all interfaces within Matter for the
 *     Matter Software Update profile, which includes the
 *     corresponding, protocol of the same name.
 */

namespace matter {
namespace Profiles {
namespace SoftwareUpdate {
  /*
   * the protocol spelled out in the profile specification comprises
   * 7 messages as described above. the image announce is optional.
   * the message type identifiers for these messages are as follows:
   */
  enum {
    kMsgType_ImageAnnounce =			0,
    kMsgType_ImageQuery = 				1,
    kMsgType_ImageQueryResponse = 		2,
    kMsgType_DownloadNotify = 			3,
    kMsgType_NotifyRepsponse = 			4, //FIXME: check the spelling!
    kMsgType_UpdateNotify =				5,
    kMsgType_ImageQueryStatus =			6, // in case the image query fails
  };
  /*
   * the software update profile defines a number of profile-specific status
   * codes.
   *
   * - kStatus_NoUpdateAvailable: server => client, indicates that an
   * image query has been recieved and understood and that the server has no
   * update for the client at this time.
   *
   * - kStatus_UpdateFailed: client => server, indicates that an attempt
   * to install an image specified by the server has failed.
   *
   * - kStatus_InvalidInstructions: client => server, indicates that
   * the client was unable to download an image because the download
   * instructions contained in the ImageQueryResponse, i.e. URI, update scheme,
   * update condition, were poorly formed or inconsistent.
   *
   * - kStatus_DownloadFailed: client => server, indicates that an
   * attempted download failed.
   *
   * - kStatus_IntegrityCheckFailed: client => server, indicates that
   * an image was downloaded but it failed the subsequent integrity check.
   *
   * - kStatus_Abort: server => client, indicates that the client
   * should give up since the server is out of options.
   *
   * - kStatus_Retry: srever => client, indicates that the client
   * should submit another image query and restart/continue the update
   * process.
   */
  enum {
    kStatus_NoUpdateAvailable =			0x0001,
    kStatus_UpdateFailed =			0x0010,
    kStatus_InvalidInstructions =		0x0050,
    kStatus_DownloadFailed =			0x0051,
    kStatus_IntegrityCheckFailed =		0x0052,
    kStatus_Abort =				0x0053,
    kStatus_Retry =				0x0091,
  };
  /*
   * the frame control field of the image query frame has the following
   * control flags
   */
  enum {
    kFlag_PackageSpecPresent =                  1,
    kFlag_LocaleSpecPresent =                   2,
    kFlag_TargetNodeIdPresent =                 4,
  };
  /*
   * the (optional) update options field of the image query response (IQR) frame
   * defines a set of bitmasks.
   */
  enum {
    kMask_UpdatePriority =			0x03, // 0b00000011
    kMask_UpdateCondition =			0x1C, // 0b00011100
    kMask_ReportStatus =			0x20, // 0b00100000
  };
  /*
   * and shift offsets
   */
  enum {
    kOffset_UpdatePriority =                    0,
    kOffset_UpdateCondition =                   2,
    kOffset_ReportStatus =                      5,
  };
  /*
   * the image query frame contains information about which integrity checking
   * the client supports and the image query response contains an integrity type
   * and value for the image that the client is being instructed to download and
   * install. the supported types are:
   */
  enum {
    kIntegrityType_SHA160 = 			0, // 160-bit Secure Hash, aka SHA-1, required
    kIntegrityType_SHA256 =				1, // 256-bit Secure Hash (SHA-2)
    kIntegrityType_SHA512 =				2, // 512-bit, Secure Hash (SHA-2)
  };
  /*
   * the lengths in bytes for the integrity specification byte-strings are as follows.
   */
  enum {
    kLength_SHA160 =					20,
    kLength_SHA256 =					32,
    kLength_SHA512 =					64,
  };
  /*
   * similarly, the image query contains information about which update
   * schemes, i.e. download protocols, the client supports, and the response
   * contains a value for indicating the update scheme to use in downloading
   * the images. the supported schemes are:
   */
  enum {
    kUpdateScheme_HTTP =				0,
    kUpdateScheme_HTTPS	=				1,
    kUpdateScheme_SFTP =				2,
    kUpdateScheme_BDX =					3, // Bulk Data Exchange protocol
  };

  /*
   * Data Element Tags for the Software Update Profile
   */
  enum
  {
    // ---- Top-level Tags ----
    //                                   Tag Type        Element Type      Disposition
    //                                   ----------------------------------------------
    kTag_InstalledLocales       = 0x00,    // Fully-Qualified  Array of strings   Required
    kTag_CertBodyId             = 0x01,    // Fully-Qualified  Integer            Required
    kTag_WirelessRegDom         = 0x02,    // Fully-Qualified  Integer            Optional
    kTag_SufficientBatterySWU   = 0x03     // Fully-Qualified  Bool               Required
  };

} // namespace SoftwareUpdate
} // namespace Profiles
} // namespace matter

#endif // _SW_UPDATE_PROFILE_H
