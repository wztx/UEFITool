/* nvramparser.cpp
 
 Copyright (c) 2016, Nikolaj Schlej. All rights reserved.
 
 This program and the accompanying materials
 are licensed and made available under the terms and conditions of the BSD License
 which accompanies this distribution.  The full text of the license may be found at
 http://opensource.org/licenses/bsd-license.php.
 
 THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 
 */

#ifdef U_ENABLE_NVRAM_PARSING_SUPPORT
#include <map>

#include "nvramparser.h"
#include "parsingdata.h"
#include "ustring.h"
#include "utility.h"
#include "nvram.h"
#include "ffs.h"
#include "intel_microcode.h"

#include "umemstream.h"
#include "kaitai/kaitaistream.h"
#include "generated/ami_nvar.h"
#include "generated/apple_sysf.h"
#include "generated/edk2_vss.h"
#include "generated/edk2_vss2.h"
#include "generated/edk2_ftw.h"
#include "generated/insyde_fdc.h"
#include "generated/phoenix_flm.h"
#include "generated/phoenix_evsa.h"

USTATUS NvramParser::parseNvarStore(const UModelIndex & index)
{
    // Sanity check
    if (!index.isValid())
        return U_INVALID_PARAMETER;

    UByteArray nvar = model->body(index);

    // Nothing to parse in an empty store
    if (nvar.isEmpty())
        return U_SUCCESS;

    // Obtain required fields from parsing data
    UINT8 emptyByte = 0xFF;
    if (model->hasEmptyParsingData(index) == false) {
        UByteArray data = model->parsingData(index);
        const VOLUME_PARSING_DATA* pdata = (const VOLUME_PARSING_DATA*)data.constData();
        emptyByte = pdata->emptyByte;
    }
    
    try {
        const UINT32 localOffset = (UINT32)model->header(index).size();
        umemstream is(nvar.constData(), nvar.size());
        kaitai::kstream ks(&is);
        ami_nvar_t parsed(&ks);

        UINT16 guidsInStore = 0;
        UINT32 currentEntryIndex = 0;
        for (const auto & entry : *parsed.entries()) {
            UINT8 subtype = Subtypes::FullNvarEntry;
            UString name;
            UString text;
            UString info;
            UString guid;
            UByteArray header;
            UByteArray body;
            UByteArray tail;

            // This is a terminating entry, needs special processing
            if (entry->_is_null_signature_rest()) {
                UINT32 guidAreaSize = guidsInStore * sizeof(EFI_GUID);
                UINT32 unparsedSize = (UINT32)nvar.size() - entry->offset() - guidAreaSize;

                // Check if the data left is a free space or a padding
                UByteArray padding = nvar.mid(entry->offset(), unparsedSize);

                // Get info
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)padding.size(), (UINT32)padding.size());

                if ((UINT32)padding.count(emptyByte) == unparsedSize) { // Free space
                    // Add tree item
                    model->addItem(localOffset + entry->offset(), Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), padding, UByteArray(), Fixed, index);
                }
                else {
                    // Nothing is parsed yet, but the file is not empty
                    if (entry->offset() == 0) {
                        msg(usprintf("%s: file can't be parsed as NVAR variable store", __FUNCTION__), index);
                        return U_SUCCESS;
                    }

                    // Add tree item
                    model->addItem(localOffset + entry->offset(), Types::Padding, getPaddingType(padding), UString("Padding"), UString(), info, UByteArray(), padding, UByteArray(), Fixed, index);
                }

                // Add GUID store area
                UByteArray guidArea = nvar.right(guidAreaSize);
                // Get info
                name = UString("GUID store");
                info = usprintf("Full size: %Xh (%u)\nGUIDs in store: %u",
                                (UINT32)guidArea.size(), (UINT32)guidArea.size(),
                                guidsInStore);
                // Add tree item
                model->addItem((UINT32)(localOffset + entry->offset() + padding.size()), Types::NvarGuidStore, 0, name, UString(), info, UByteArray(), guidArea, UByteArray(), Fixed, index);

                return U_SUCCESS;
            }

            // This is a normal entry
            const auto entry_body = entry->body();

            // Set default next to predefined last value
            NVAR_ENTRY_PARSING_DATA pdata = {};
            pdata.emptyByte = emptyByte;
            pdata.next = 0xFFFFFF;
            pdata.isValid = TRUE;

            // Check for invalid entry
            if (!entry->attributes()->valid()) {
                subtype = Subtypes::InvalidNvarEntry;
                name = UString("Invalid");
                pdata.isValid = FALSE;
                goto processing_done;
            }

            // Check for link entry
            if (entry->next() != 0xFFFFFF) {
                subtype = Subtypes::LinkNvarEntry;
                pdata.next = (UINT32)entry->next();
            }

            // Check for data-only entry (nameless and GUIDless entry or link)
            if (entry->attributes()->data_only()) {
                // Search backwards for a previous entry with a link to this variable
                UModelIndex prevEntryIndex;
                if (currentEntryIndex > 0) {
                    for (UINT32 i = currentEntryIndex - 1; i > 0; i--) {
                        const auto & previousEntry = parsed.entries()->at(i);

                        if (previousEntry == entry)
                            break;

                        if ((UINT32)previousEntry->next() + (UINT32)previousEntry->offset() == (UINT32)entry->offset()) { // Previous link is present and valid
                            prevEntryIndex = index.model()->index(i, 0, index);
                            // Make sure that we are linking to a valid entry
                            NVAR_ENTRY_PARSING_DATA pd = readUnaligned((NVAR_ENTRY_PARSING_DATA*)model->parsingData(prevEntryIndex).constData());
                            if (!pd.isValid) {
                                prevEntryIndex = UModelIndex();
                            }
                            break;
                        }
                    }
                }
                // Check if the link is valid
                if (prevEntryIndex.isValid()) {
                    // Use the name and text of the previous entry
                    name = model->name(prevEntryIndex);
                    text = model->text(prevEntryIndex);

                    if (entry->next() == 0xFFFFFF)
                        subtype = Subtypes::DataNvarEntry;
                }
                else {
                    subtype = Subtypes::InvalidLinkNvarEntry;
                    name = UString("InvalidLink");
                    pdata.isValid = FALSE;
                }
                goto processing_done;
            }

            // Obtain text
            if (!entry_body->_is_null_ascii_name()) {
                text = entry_body->ascii_name().c_str();
            }
            else if (!entry_body->_is_null_ucs2_name()) {
                UByteArray temp;
                for (const auto & ch : *entry_body->ucs2_name()->ucs2_chars()) {
                    temp += UByteArray((const char*)&ch, sizeof(ch));
                }
                text = uFromUcs2(temp.constData());
            }

            // Obtain GUID
            if (!entry_body->_is_null_guid()) { // GUID is stored in the entry itself
                const EFI_GUID g = readUnaligned((EFI_GUID*)entry_body->guid().c_str());
                name = guidToUString(g);
                guid = guidToUString(g, false);
            }
            else { // GUID is stored in GUID store at the end of the NVAR store
                // Grow the GUID store if needed
                if (guidsInStore < entry_body->guid_index() + 1)
                    guidsInStore = entry_body->guid_index() + 1;

                // The list begins at the end of the store and goes backwards
                const EFI_GUID g = readUnaligned((EFI_GUID*)(nvar.constData() + nvar.size()) - (entry_body->guid_index() + 1));
                name = guidToUString(g);
                guid = guidToUString(g, false);
            }

processing_done:
            // This feels hacky, but I haven't found a way to ask Kaitai for raw bytes
            header = nvar.mid(entry->offset(), sizeof(NVAR_ENTRY_HEADER) + entry_body->data_start_offset());
            body = nvar.mid(entry->offset() + sizeof(NVAR_ENTRY_HEADER) + entry_body->data_start_offset(), entry_body->data_size());
            tail = nvar.mid(entry->end_offset() - entry_body->extended_header_size(), entry_body->extended_header_size());

            // Add GUID info for valid entries
            if (!guid.isEmpty())
                info += UString("Variable GUID: ") + guid + "\n";

            // Add GUID index information
            if (!entry_body->_is_null_guid_index())
                info += usprintf("GUID index: %u\n", entry_body->guid_index());

            // Add header, body and extended data info
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nTail size: %Xh (%u)",
                             entry->size(), entry->size(),
                             (UINT32)header.size(), (UINT32)header.size(),
                             (UINT32)body.size(), (UINT32)body.size(),
                             (UINT32)tail.size(), (UINT32)tail.size());

            // Add attributes info
            const NVAR_ENTRY_HEADER entryHeader = readUnaligned((NVAR_ENTRY_HEADER*)header.constData());
            info += usprintf("\nAttributes: %02Xh", entryHeader.Attributes);

            // Translate attributes to text
            if (entryHeader.Attributes != 0x00 && entryHeader.Attributes != 0xFF)
                info += UString(" (") + nvarAttributesToUString(entryHeader.Attributes) + UString(")");

            // Add next node info
            if (entry->next() != 0xFFFFFF)
                info += usprintf("\nNext node at offset: %Xh", localOffset + entry->offset() + (UINT32)entry->next());

            // Add extended header info
            if (entry_body->extended_header_size() > 0) {
                info += usprintf("\nExtended header size: %Xh (%u)",
                                 entry_body->extended_header_size(), entry_body->extended_header_size());

                const UINT8 extendedAttributes = *tail.constData();
                info += usprintf("\nExtended attributes: %02Xh (", extendedAttributes) + nvarExtendedAttributesToUString(extendedAttributes) + UString(")");

                // Add checksum
                if (!entry_body->_is_null_extended_header_checksum()) {
                    UINT8 calculatedChecksum = 0;
                    UByteArray wholeBody = body + tail;

                    // Include entry body
                    UINT8* start = (UINT8*)wholeBody.constData();
                    for (UINT8* p = start; p < start + wholeBody.size(); p++) {
                        calculatedChecksum += *p;
                    }
                    // Include entry size and flags
                    start = (UINT8*)&entryHeader.Size;
                    for (UINT8*p = start; p < start + sizeof(UINT16); p++) {
                        calculatedChecksum += *p;
                    }
                    // Include entry attributes
                    calculatedChecksum += entryHeader.Attributes;
                    info += usprintf("\nChecksum: %02Xh, ", entry_body->extended_header_checksum())
                     + (calculatedChecksum ? usprintf(", invalid, should be %02Xh", 0x100 - calculatedChecksum) : UString(", valid"));
                }

                // Add timestamp
                if (!entry_body->_is_null_extended_header_timestamp())
                    info += usprintf("\nTimestamp: %" PRIX64 "h", entry_body->extended_header_timestamp());

                // Add hash
                if (!entry_body->_is_null_extended_header_hash()) {
                    UByteArray hash = UByteArray(entry_body->extended_header_hash().c_str(), entry_body->extended_header_hash().size());
                    info += UString("\nHash: ") + UString(hash.toHex().constData());
                }
            }

            // Add tree item
            UModelIndex varIndex = model->addItem(localOffset + entry->offset(), Types::NvarEntry, subtype, name, text, info, header, body, tail, Fixed, index);
            currentEntryIndex++;

            // Set parsing data
            model->setParsingData(varIndex, UByteArray((const char*)&pdata, sizeof(pdata)));

            // Try parsing the entry data as NVAR storage if it begins with NVAR signature
            if ((subtype == Subtypes::DataNvarEntry || subtype == Subtypes::FullNvarEntry)
                && body.size() >= 4 && readUnaligned((const UINT32*)body.constData()) == NVRAM_NVAR_ENTRY_SIGNATURE)
                (void)parseNvarStore(varIndex);
        }
    }
    catch (...) {
        msg(usprintf("%s: unable to parse AMI NVAR storage", __FUNCTION__), index);
        return U_INVALID_STORE;
    }

    return U_SUCCESS;
}

USTATUS NvramParser::parseNvramVolumeBody(const UModelIndex & index,const UINT32 fdcStoreSizeOverride)
{
    // Sanity check
    if (!index.isValid())
        return U_INVALID_PARAMETER;
    
    // Obtain required fields from parsing data
    UINT8 emptyByte = 0xFF;
    if (model->hasEmptyParsingData(index) == false) {
        UByteArray data = model->parsingData(index);
        const VOLUME_PARSING_DATA* pdata = (const VOLUME_PARSING_DATA*)data.constData();
        emptyByte = pdata->emptyByte;
    }
    
    // Get local offset
    const UINT32 localOffset = (UINT32)model->header(index).size();
    
    // Get item data
    UByteArray volumeBody = model->body(index);
    const UINT32 volumeBodySize = (UINT32)volumeBody.size();

    // Iterate over all bytes inside the volume body, trying to parse every next byte offset by one of the known parsers
    UByteArray outerPadding;
    UINT32 previousStoreEndOffset = 0;
    for (UINT32 storeOffset = 0;
         storeOffset < volumeBodySize;
         storeOffset++) {
        UString name, text, info;
        UByteArray header, body;
        
        // VSS
        try {
            if (volumeBodySize - storeOffset < sizeof(VSS_VARIABLE_STORE_HEADER)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray vss = volumeBody.mid(storeOffset);
            // Check if we are here to parse a special case of FDC store with size override
            UINT32 originalStoreSize = 0;
            VSS_VARIABLE_STORE_HEADER* vssHeader = (VSS_VARIABLE_STORE_HEADER*)vss.data();
            bool fdcHeaderSizeOverrideRequired = (fdcStoreSizeOverride > 0 && vssHeader->Signature == NVRAM_VSS_STORE_SIGNATURE && vssHeader->Size == 0xFFFFFFFF);
            if (fdcHeaderSizeOverrideRequired) {
                originalStoreSize = vssHeader->Size;
                vssHeader->Size = fdcStoreSizeOverride;
            }
            umemstream is(vss.constData(), vss.size());
            kaitai::kstream ks(&is);
            edk2_vss_t parsed(&ks);
            UINT32 storeSize = parsed.vss_size();
            // Restore original store size, if needed
            if (fdcHeaderSizeOverrideRequired) {
                vssHeader->Size = originalStoreSize;
            }

            // VSS store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }

            // Construct header and body
            header = vss.left(parsed.len_vss_store_header());
            body = vss.mid(header.size(), storeSize - header.size());
            
            // Add info
            if (parsed.signature() == NVRAM_APPLE_SVS_STORE_SIGNATURE) {
                name = UString("SVS store");
            }
            else if (parsed.signature() == NVRAM_APPLE_NSS_STORE_SIGNATURE) {
                name = UString("NSS store");
            }
            else {
                name = UString("VSS store");
            }
            info = usprintf("Signature: %Xh (", parsed.signature()) + fourCC(parsed.signature()) + UString(")\n");
            
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nFormat: %02Xh\nState: %02Xh\nReserved: %02Xh\nReserved1: %04Xh",
                            storeSize , storeSize,
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.format(),
                            parsed.state(),
                            parsed.reserved(),
                            parsed.reserved1());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::VssStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Add variables
            UINT32 vssVariableOffset = parsed.len_vss_store_header();
            for (const auto & variable : *parsed.body()->variables()) {
                UINT8 subtype;
                
                // This is the terminating entry, needs special processing
                if (variable->_is_null_signature_last()) {
                    // Add free space or padding after all variables, if needed
                    if (vssVariableOffset < storeSize) {
                        UByteArray freeSpace = vss.mid(vssVariableOffset, storeSize - vssVariableOffset);
                        // Add info
                        info = usprintf("Full size: %Xh (%u)", (UINT32)freeSpace.size(), (UINT32)freeSpace.size());
                        
                        // Check that remaining unparsed bytes are actually empty
                        if (freeSpace.count(emptyByte) == freeSpace.size()) { // Free space
                            // Add tree item
                            model->addItem(vssVariableOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                        else {
                            // Add tree item
                            model->addItem(vssVariableOffset, Types::Padding, getPaddingType(freeSpace), UString("Padding"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                    }
                    break;
                }
                
                // This is a normal entry
                UINT32 variableSize;
                if (variable->is_intel_legacy()) { // Intel legacy
                    subtype = Subtypes::IntelVssEntry;
                    // Needs some additional parsing of variable->intel_legacy_data to separate the name from the value
                    text = uFromUcs2(variable->intel_legacy_data().c_str());
                    UINT32 textLengthInBytes = (UINT32)text.length()*2+2;
                    header = vss.mid(vssVariableOffset, variable->len_intel_legacy_header() + textLengthInBytes);
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_total() - variable->len_intel_legacy_header() - textLengthInBytes);
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else if (variable->is_auth()) { // Authenticated
                    subtype = Subtypes::AuthVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_auth_header() + variable->len_name_auth());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data_auth());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name_auth().c_str());
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else if (!variable->_is_null_apple_data_crc32()) { // Apple CRC32
                    subtype = Subtypes::AppleVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_apple_header() + variable->len_name());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else { // Standard
                    subtype = Subtypes::StandardVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_standard_header() + variable->len_name());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                
                // Override variable type to Invalid if needed
                if (!variable->is_valid()) {
                    subtype = Subtypes::InvalidVssEntry;
                    name = UString("Invalid");
                    text.clear();
                }
                
                const UINT32 variableAttributes = variable->attributes()->non_volatile()
                + (variable->attributes()->boot_service() << 1)
                + (variable->attributes()->runtime() << 2)
                + (variable->attributes()->hw_error_record() << 3)
                + (variable->attributes()->auth_write() << 4)
                + (variable->attributes()->time_based_auth() << 5)
                + (variable->attributes()->append_write() << 6)
                + (UINT32)(variable->attributes()->reserved() << 7)
                + (variable->attributes()->apple_data_checksum() << 31);
                
                // Add generic info
                info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nState: %02Xh\nReserved: %02Xh\nAttributes: %08Xh (",
                                 variableSize, variableSize,
                                 (UINT32)header.size(), (UINT32)header.size(),
                                 (UINT32)body.size(), (UINT32)body.size(),
                                 variable->state(),
                                 variable->reserved(),
                                 variableAttributes) + vssAttributesToUString(variableAttributes) + UString(")");
                
                // Add specific info
                if (variable->is_auth()) {
                    UINT64 monotonicCounter = (UINT64)variable->len_name() + ((UINT64)variable->len_data() << 32);
                    info += usprintf("\nMonotonic counter: %" PRIX64 "h\nTimestamp: ", monotonicCounter) + efiTimeToUString(*(const EFI_TIME*)variable->timestamp().c_str())
                    + usprintf("\nPubKey index: %u", variable->pubkey_index());
                }
                else if (!variable->_is_null_apple_data_crc32()) {
                    // Calculate CRC32 of the variable data
                    UINT32 calculatedCrc32 = (UINT32)crc32(0, (const UINT8*)body.constData(), (uInt)body.size());
                    
                    info += usprintf("\nData checksum: %08Xh", variable->apple_data_crc32()) +
                    (variable->apple_data_crc32() != calculatedCrc32 ? usprintf(", invalid, should be %08Xh", calculatedCrc32) : UString(", valid"));
                }
                
                // Add tree item
                model->addItem(vssVariableOffset, Types::VssEntry, subtype, name, text, info, header, body, UByteArray(), Fixed, headerIndex);
                
                vssVariableOffset += variableSize;
            }
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
           // Parsing failed, try something else
        }

        // VSS2
        try {
            if (volumeBodySize - storeOffset < sizeof(VSS2_VARIABLE_STORE_HEADER)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray vss2 = volumeBody.mid(storeOffset);
            
            // Check if we are here to parse a special case of FDC store with size override
            UINT32 originalStoreSize = 0;
            VSS2_VARIABLE_STORE_HEADER* vss2Header = (VSS2_VARIABLE_STORE_HEADER*)vss2.data();
            UByteArray guid = UByteArray((const char*)&vss2Header->Signature, sizeof(EFI_GUID));
            bool fdcHeaderSizeOverrideRequired = (fdcStoreSizeOverride > 0 && guid == NVRAM_FDC_STORE_GUID && vss2Header->Size == 0xFFFFFFFF);
            if (fdcHeaderSizeOverrideRequired) {
                originalStoreSize = vss2Header->Size;
                vss2Header->Size = fdcStoreSizeOverride;
            }
            
            umemstream is(vss2.constData(), vss2.size());
            kaitai::kstream ks(&is);
            edk2_vss2_t parsed(&ks);
            UINT32 storeSize = parsed.vss2_size();
            
            // Restore original store size, if needed
            if (fdcHeaderSizeOverrideRequired) {
                vss2Header->Size = originalStoreSize;
            }
            
            // VSS2 store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }

            // Construct header and body
            header = vss2.left(parsed.len_vss2_store_header());
            body = vss2.mid(header.size(), storeSize - header.size());
            
            // Add info
            name = UString("VSS2 store");
            if (parsed.signature() == NVRAM_VSS2_AUTH_VAR_KEY_DATABASE_GUID_PART1) {
                info = UString("Signature: AAF32C78-947B-439A-A180-2E144EC37792\n");
            }
            else if (parsed.signature() == NVRAM_FDC_STORE_GUID_PART1) {
                info = UString("Signature: DDCF3616-3275-4164-98B6-FE85707FFE7D\n");
            }
            else {
                info = UString("Signature: DDCF3617-3275-4164-98B6-FE85707FFE7D\n");
            }
            
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nFormat: %02Xh\nState: %02Xh\nReserved: %02Xh\nReserved1: %04Xh",
                            storeSize, storeSize,
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.format(),
                            parsed.state(),
                            parsed.reserved(),
                            parsed.reserved1());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::Vss2Store, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Add variables
            UINT32 vss2VariableOffset = parsed.len_vss2_store_header();
            for (const auto & variable : *parsed.body()->variables()) {
                UINT8 subtype;
                
                // This is the terminating entry, needs special processing
                if (variable->_is_null_signature_last()) {
                    // Add free space or padding after all variables, if needed
                    if (vss2VariableOffset < storeSize) {
                        UByteArray freeSpace = vss2.mid(vss2VariableOffset, storeSize - vss2VariableOffset);
                        // Add info
                        info = usprintf("Full size: %Xh (%u)", (UINT32)freeSpace.size(), (UINT32)freeSpace.size());
                        
                        // Check that remaining unparsed bytes are actually empty
                        if (freeSpace.count(emptyByte) == freeSpace.size()) { // Free space
                            // Add tree item
                            model->addItem(vss2VariableOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                        else {
                            // Add tree item
                            model->addItem(vss2VariableOffset, Types::Padding, getPaddingType(freeSpace), UString("Padding"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                    }
                    break;
                }
                
                // This is a normal entry
                UINT32 variableSize;
                UINT32 alignmentSize;
                if (variable->is_auth()) { // Authenticated
                    subtype = Subtypes::AuthVssEntry;
                    header = vss2.mid(vss2VariableOffset, variable->len_auth_header() + variable->len_name_auth());
                    body = vss2.mid(vss2VariableOffset + header.size(), variable->len_data_auth());
                    variableSize = (UINT32)(header.size() + body.size());
                    alignmentSize = variable->len_alignment_padding_auth();
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name_auth().c_str());
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else { // Standard
                    subtype = Subtypes::StandardVssEntry;
                    header = vss2.mid(vss2VariableOffset, variable->len_standard_header() + variable->len_name());
                    body = vss2.mid(vss2VariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    alignmentSize = variable->len_alignment_padding();
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info = UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                
                // Override variable type to Invalid if needed
                if (!variable->is_valid()) {
                    subtype = Subtypes::InvalidVssEntry;
                    name = UString("Invalid");
                    text.clear();
                }
                
                const UINT32 variableAttributes = variable->attributes()->non_volatile()
                + (variable->attributes()->boot_service() << 1)
                + (variable->attributes()->runtime() << 2)
                + (variable->attributes()->hw_error_record() << 3)
                + (variable->attributes()->auth_write() << 4)
                + (variable->attributes()->time_based_auth() << 5)
                + (variable->attributes()->append_write() << 6)
                + (UINT32)(variable->attributes()->reserved() << 7);
                
                // Add generic info
                info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nState: %02Xh\nReserved: %02Xh\nAttributes: %08Xh (",
                                 variableSize, variableSize,
                                 (UINT32)header.size(), (UINT32)header.size(),
                                 (UINT32)body.size(), (UINT32)body.size(),
                                 variable->state(),
                                 variable->reserved(),
                                 variableAttributes) + vssAttributesToUString(variableAttributes) + UString(")");
                
                // Add specific info
                if (variable->is_auth()) {
                    UINT64 monotonicCounter = (UINT64)variable->len_name() + ((UINT64)variable->len_data() << 32);
                    info += usprintf("\nMonotonic counter: %" PRIX64 "h\nTimestamp: ", monotonicCounter) + efiTimeToUString(*(const EFI_TIME*)variable->timestamp().c_str())
                    + usprintf("\nPubKey index: %u", variable->pubkey_index());
                }
                
                // Add tree item
                model->addItem(vss2VariableOffset, Types::VssEntry, subtype, name, text, info, header, body, UByteArray(), Fixed, headerIndex);
                
                vss2VariableOffset += (variableSize + alignmentSize);
            }
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
           // Parsing failed, try something else
        }
        
        // Do not try any other parsers if we are here for FDC store parsing
        if (fdcStoreSizeOverride != 0) {
            continue;
        }
        
        // FTW
        try {
            if (volumeBodySize - storeOffset < sizeof(EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER32)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray ftw = volumeBody.mid(storeOffset);
            umemstream is(ftw.constData(), ftw.size());
            kaitai::kstream ks(&is);
            edk2_ftw_t parsed(&ks);
            UINT64 storeSize;
            UINT64 headerSize;
            UINT32 calculatedCrc;
            if (parsed._is_null_len_write_queue_64()) {
                headerSize = parsed.len_ftw_store_header_32();
                storeSize = headerSize + parsed.len_write_queue_32();
                header = ftw.left(headerSize);
                
                // Check block header checksum
                UByteArray crcHeader = header;
                EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER32* crcFtwBlockHeader = (EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER32*)crcHeader.data();
                crcFtwBlockHeader->Crc = emptyByte ? 0xFFFFFFFF : 0;
                crcFtwBlockHeader->State = emptyByte ? 0xFF : 0;
                calculatedCrc = (UINT32)crc32(0, (const UINT8*)crcFtwBlockHeader, (UINT32)headerSize);
            }
            else {
                headerSize = parsed.len_ftw_store_header_64();
                storeSize = headerSize + parsed.len_write_queue_32() + (((UINT64)parsed.len_write_queue_64()) << 32);
                header = ftw.left(headerSize);
                
                // Check block header checksum
                UByteArray crcHeader = header;
                EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER64* crcFtwBlockHeader = (EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER64*)crcHeader.data();
                crcFtwBlockHeader->Crc = emptyByte ? 0xFFFFFFFF : 0;
                crcFtwBlockHeader->State = emptyByte ? 0xFF : 0;
                calculatedCrc = (UINT32)crc32(0, (const UINT8*)crcFtwBlockHeader, (UINT32)headerSize);
            }
            
            // FTW store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }
            
            // Construct header and body
            body = ftw.mid(header.size(), storeSize - header.size());
            
            // Add info
            const EFI_GUID* guid = (const EFI_GUID*)header.constData();
            name = UString("FTW store");
            info = UString("Signature: ") + guidToUString(*guid, false);
            info += usprintf("\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nState: %02Xh\nHeader CRC32: %08Xh",
                             (UINT32)storeSize, (UINT32)storeSize,
                             (UINT32)header.size(), (UINT32)header.size(),
                             (UINT32)body.size(), (UINT32)body.size(),
                             parsed.state(),
                             parsed.crc()) + (parsed.crc() != calculatedCrc ? usprintf(", invalid, should be %08Xh", calculatedCrc) : UString(", valid"));
            
            // Add header tree item
            model->addItem(localOffset + storeOffset, Types::FtwStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        
        // Insyde FDC
        try {
            if (volumeBodySize - storeOffset < sizeof(FDC_VOLUME_HEADER)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray fdc = volumeBody.mid(storeOffset);
            umemstream is(fdc.constData(), fdc.size());
            kaitai::kstream ks(&is);
            insyde_fdc_t parsed(&ks);
            UINT32 storeSize = parsed.fdc_size();
            
            // FDC store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }
            
            // Construct header and body
            header = fdc.left(parsed.len_fdc_store_header());
            body = fdc.mid(header.size(),storeSize - header.size());
            
            // Add info
            name = UString("FDC store");
            info = usprintf("Signature: _FDC\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)",
                                    storeSize, storeSize,
                                    (UINT32)header.size(), (UINT32)header.size(),
                                    (UINT32)body.size(), (UINT32)body.size());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::FdcStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Parse FDC body as normal VSS/VSS2 storage with size override
            parseNvramVolumeBody(headerIndex, (UINT32)body.size());
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        
        // Apple SysF
        try {
            if (volumeBodySize - storeOffset < sizeof(APPLE_SYSF_STORE_HEADER)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray sysf = volumeBody.mid(storeOffset);
            umemstream is(sysf.constData(), sysf.size());
            kaitai::kstream ks(&is);
            apple_sysf_t parsed(&ks);
            UINT32 storeSize = parsed.sysf_size();
            
            // Apple SysF store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }
            
            // Construct header and body
            header = sysf.left(parsed.len_sysf_store_header());
            body = sysf.mid(header.size(), storeSize - header.size());
            
            // Check store checksum
            UINT32 calculatedCrc = (UINT32)crc32(0, (const UINT8*)sysf.constData(), storeSize - sizeof(UINT32));
            
            // Add info
            if (parsed.signature() == NVRAM_APPLE_SYSF_STORE_SIGNATURE) {
                name = UString("SysF store");
                info = UString("Signature: Fsys\n");
            }
            else {
                name = UString("Diag store");
                info = UString("Signature: Gaid\n");
            }
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nUnknown: %02Xh\nUnknown1: %08Xh\nCRC32: %08Xh",
                            storeSize, storeSize,
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.unknown(),
                            parsed.unknown1(),
                            parsed.crc())  + (parsed.crc() != calculatedCrc ? usprintf(", invalid, should be %08Xh", calculatedCrc) : UString(", valid"));
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::SysFStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Add variables
            UINT32 sysfVariableOffset = parsed.len_sysf_store_header();
            for (const auto & variable : *parsed.body()->variables()) {
                UINT8 subtype;
                
                if (variable->invalid_flag()) {
                    subtype = Subtypes::InvalidSysFEntry;
                    name = UString("Invalid");
                }
                else {
                    subtype = Subtypes::NormalSysFEntry;
                    name = usprintf("%s", variable->name().c_str());
                }
                
                if (variable->len_name() == 3 && variable->name() == "EOF") {
                    header = sysf.mid(sysfVariableOffset, 4);
                }
                else {
                    header = sysf.mid(sysfVariableOffset, sizeof(UINT8) + (UINT32)variable->len_name() + sizeof(UINT16));
                    body = sysf.mid(sysfVariableOffset + header.size(), (UINT32)variable->len_data());
                }
                // Add generic info
                UINT32 variableSize = (UINT32)header.size() + (UINT32)body.size();
                info = usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\n",
                                 variableSize, variableSize,
                                 (UINT32)header.size(), (UINT32)header.size(),
                                 (UINT32)body.size(), (UINT32)body.size());
                
                // Add tree item
                model->addItem(sysfVariableOffset, Types::SysFEntry, subtype, name, UString(), info, header, body, UByteArray(), Fixed, headerIndex);
                
                sysfVariableOffset += variableSize;
            }
            
            // Add free space or padding after all variables, if needed
            if (sysfVariableOffset < storeSize) {
                UByteArray freeSpace = sysf.mid(sysfVariableOffset, storeSize - sysfVariableOffset);
                // Add info
                info = usprintf("Full size: %Xh (%u)", (UINT32)freeSpace.size(), (UINT32)freeSpace.size());
                
                // Check that remaining unparsed bytes are actually zeroes
                if (freeSpace.count('\x00') == freeSpace.size() - 4) { // Free space, 4 last bytes are always CRC32
                    // Add tree item
                    model->addItem(sysfVariableOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                }
                else {
                    // Add tree item
                    model->addItem(sysfVariableOffset, Types::Padding, getPaddingType(freeSpace), UString("Padding"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                }
            }
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        
        // Phoenix SCT FlashMap
        try {
            if (volumeBodySize - storeOffset < NVRAM_PHOENIX_FLASH_MAP_TOTAL_SIZE) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray flm = volumeBody.mid(storeOffset);
            umemstream is(flm.constData(), flm.size());
            kaitai::kstream ks(&is);
            phoenix_flm_t parsed(&ks);
            UINT32 storeSize = parsed.len_flm_store();
            
            // Phoenix FlashMap store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }
            
            // Construct header and body
            header = flm.left(parsed.len_flm_store_header());
            body = flm.mid(header.size(), storeSize - header.size());
            
            // Add info
            name = UString("Phoenix SCT FlashMap");
            info = usprintf("Signature: _FLASH_MAP\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nEntries: %u\nReserved: %08Xh",
                                    storeSize, storeSize,
                                    (UINT32)header.size(), (UINT32)header.size(),
                                    (UINT32)body.size(), (UINT32)body.size(),
                                    parsed.num_entries(),
                                    parsed.reserved());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::PhoenixFlashMapStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Add entries
            UINT32 entryOffset = parsed.len_flm_store_header();
            for (const auto & entry : *parsed.entries()) {
                UINT8 subtype;
                
                if (entry->data_type() == NVRAM_PHOENIX_FLASH_MAP_ENTRY_DATA_TYPE_VOLUME) {
                    subtype = Subtypes::VolumeFlashMapEntry;
                }
                else if (entry->data_type() == NVRAM_PHOENIX_FLASH_MAP_ENTRY_DATA_TYPE_DATA_BLOCK) {
                    subtype = Subtypes::DataFlashMapEntry;
                }
                else {
                    subtype = Subtypes::UnknownFlashMapEntry;
                }
                
                const EFI_GUID guid = readUnaligned((const EFI_GUID*)entry->guid().c_str());
                name = guidToUString(guid);
                text = phoenixFlashMapGuidToUString(guid);
                header = flm.mid(entryOffset, parsed.len_flm_entry());

                // Add info
                UINT32 entrySize = (UINT32)header.size();
                info = usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: 0h (0)\nData type: %04Xh\nEntry type: %04Xh\nSize: %08Xh\nOffset: %08Xh\nPhysical address: %" PRIX64 "h",
                                entrySize, entrySize,
                                (UINT32)header.size(), (UINT32)header.size(),
                                entry->data_type(),
                                entry->entry_type(),
                                entry->size(),
                                entry->offset(),
                                entry->physical_address());
                
                // Add tree item
                model->addItem(entryOffset, Types::PhoenixFlashMapEntry, subtype, name, text, info, header, UByteArray(), UByteArray(), Fixed, headerIndex);
                
                entryOffset += entrySize;
            }
            
            // Add free space, if needed
            UByteArray freeSpace;
            for (const auto & byte : *parsed.free_space()) {
                freeSpace += (const char)byte;
            }
            if (freeSpace.size() > 0) {
                // Add info
                info = usprintf("Full size: %Xh (%u)", (UINT32)freeSpace.size(), (UINT32)freeSpace.size());
                
                // Check that remaining unparsed bytes are actually zeroes
                if (freeSpace.count(emptyByte) == freeSpace.size()) { // Free space
                    // Add tree item
                    model->addItem(entryOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                }
                else {
                    // Add tree item
                    model->addItem(entryOffset, Types::Padding, getPaddingType(freeSpace), UString("Padding"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                }
            }
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        
        // Phoenix EVSA
        try {
            if (volumeBodySize - storeOffset < sizeof(EVSA_STORE_ENTRY)) {
                // No need to parse further, the rest of the volume is too small
                throw 0;
            }
            
            UByteArray evsa = volumeBody.mid(storeOffset);
            umemstream is(evsa.constData(), evsa.size());
            kaitai::kstream ks(&is);
            phoenix_evsa_t parsed(&ks);
            UINT32 storeSize = parsed.len_evsa_store();
            
            // Phoenix EVSA store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }
            
            // Construct header and body
            header = evsa.left(parsed.len_evsa_store_header());
            body = evsa.mid(header.size(), storeSize - header.size());
            
            const EVSA_STORE_ENTRY* evsaStoreHeader = (const EVSA_STORE_ENTRY*)header.constData();
            UINT8 calculated = calculateChecksum8(((const UINT8*)evsaStoreHeader) + 2, evsaStoreHeader->Header.Size - 2);
            
            // Add info
            name = UString("EVSA Store");
            info = usprintf("Signature: EVSA\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nAttributes: %08Xh\nReserved: %08Xh\nChecksum: %02Xh",
                            storeSize, storeSize,
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.attributes(),
                            parsed.reserved(),
                            parsed.checksum())
            + (parsed.checksum() != calculated ? usprintf(", invalid, should be %02Xh", calculated) : UString(", valid"));
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::EvsaStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            // Add entries
            std::map<UINT16, EFI_GUID> guidMap;
            std::map<UINT16, UString> nameMap;
            UINT32 entryOffset = parsed.len_evsa_store_header();
            for (const auto & entry : *parsed.body()->entries()) {
                UINT8 subtype;
                UINT32 entrySize;
                
                // This is the terminating entry, needs special processing
                if (entry->_is_null_checksum()) {
                    // Add free space or padding after all variables, if needed
                    if (entryOffset < storeSize) {
                        UByteArray freeSpace = evsa.mid(entryOffset, storeSize - entryOffset);
                        // Add info
                        info = usprintf("Full size: %Xh (%u)", (UINT32)freeSpace.size(), (UINT32)freeSpace.size());
                        
                        // Check that remaining unparsed bytes are actually empty
                        if (freeSpace.count(emptyByte) == freeSpace.size()) { // Free space
                            // Add tree item
                            model->addItem(entryOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                        else {
                            // Add tree item
                            model->addItem(entryOffset, Types::Padding, getPaddingType(freeSpace), UString("Padding"), UString(), info, UByteArray(), freeSpace, UByteArray(), Fixed, headerIndex);
                        }
                    }
                    break;
                }
                
                const EVSA_ENTRY_HEADER* entryHeader = (const EVSA_ENTRY_HEADER*)(evsa.constData() + entryOffset);
                calculated = calculateChecksum8(((const UINT8*)entryHeader) + 2, entryHeader->Size - 2);
                
                // GUID entry
                if (entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_GUID1 || entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_GUID2) {
                    const phoenix_evsa_t::evsa_guid_t* guidEntry = (const phoenix_evsa_t::evsa_guid_t*)(entry->body());
                    header = evsa.mid(entryOffset, sizeof(EVSA_GUID_ENTRY));
                    body = evsa.mid(entryOffset + sizeof(EVSA_GUID_ENTRY), entry->len_evsa_entry() - header.size());
                    entrySize = (UINT32)(header.size() + body.size());
                    EFI_GUID guid = *(const EFI_GUID*)(guidEntry->guid().c_str());
                    name = guidToUString(guid);
                    info = UString("GUID: ") + guidToUString(guid, false)
                    + usprintf("\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nType: %02Xh\nChecksum: %02Xh",
                               entrySize, entrySize,
                               (UINT32)header.size(), (UINT32)header.size(),
                               (UINT32)body.size(), (UINT32)body.size(),
                               entry->entry_type(),
                               entry->checksum())
                    + (entry->checksum() != calculated ? usprintf(", invalid, should be %02Xh", calculated) : UString(", valid"))
                    + usprintf("\nGuidId: %04Xh", guidEntry->guid_id());
                    subtype = Subtypes::GuidEvsaEntry;
                    guidMap.insert(std::pair<UINT16, EFI_GUID>(guidEntry->guid_id(), guid));
                }
                // Name entry
                else if (entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_NAME1 || entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_NAME2) {
                    const phoenix_evsa_t::evsa_name_t* nameEntry = (const phoenix_evsa_t::evsa_name_t*)(entry->body());
                    header = evsa.mid(entryOffset, sizeof(EVSA_NAME_ENTRY));
                    body = evsa.mid(entryOffset + sizeof(EVSA_NAME_ENTRY), entry->len_evsa_entry() - header.size());
                    entrySize = (UINT32)(header.size() + body.size());
                    name = uFromUcs2(body.constData());
                    info = UString("Name: ") + name
                    + usprintf("\nFull size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nType: %02Xh\nChecksum: %02Xh",
                               entrySize, entrySize,
                               (UINT32)header.size(), (UINT32)header.size(),
                               (UINT32)body.size(), (UINT32)body.size(),
                               entry->entry_type(),
                               entry->checksum())
                    + (entry->checksum() != calculated ? usprintf(", invalid, should be %02Xh", calculated) : UString(", valid"))
                    + usprintf("\nVarId: %04Xh", nameEntry->var_id());
                    subtype = Subtypes::NameEvsaEntry;
                    nameMap.insert(std::pair<UINT16, UString>(nameEntry->var_id(), name));
                }
                // Data entry
                else if (entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_DATA1
                         || entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_DATA2
                         || entry->entry_type() == NVRAM_EVSA_ENTRY_TYPE_DATA_INVALID) {
                    phoenix_evsa_t::evsa_data_t* dataEntry = (phoenix_evsa_t::evsa_data_t*)(entry->body());
                    if (dataEntry->_is_null_len_data_ext()) {
                        header = evsa.mid(entryOffset, sizeof(EVSA_DATA_ENTRY));
                        body = evsa.mid(entryOffset + sizeof(EVSA_DATA_ENTRY), entry->len_evsa_entry() - header.size());
                    }
                    else {
                        header = evsa.mid(entryOffset, sizeof(EVSA_DATA_ENTRY_EXTENDED));
                        body = evsa.mid(entryOffset + sizeof(EVSA_DATA_ENTRY_EXTENDED), dataEntry->len_data_ext());
                    }
                    entrySize = (UINT32)(header.size() + body.size());
                    name = UString("Data");
                    subtype = Subtypes::DataEvsaEntry;
                    
                    const UINT32 attributes = dataEntry->attributes()->non_volatile()
                    + (dataEntry->attributes()->boot_service() << 1)
                    + (dataEntry->attributes()->runtime() << 2)
                    + (dataEntry->attributes()->hw_error_record() << 3)
                    + (dataEntry->attributes()->auth_write() << 4)
                    + (dataEntry->attributes()->time_based_auth() << 5)
                    + (dataEntry->attributes()->append_write() << 6)
                    + (UINT32)(dataEntry->attributes()->reserved() << 7)
                    + (dataEntry->attributes()->extended_header() << 28)
                    + (UINT32)(dataEntry->attributes()->reserved1() << 29);
                    
                    info = usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nType: %02Xh\nChecksum: %02Xh",
                                    entrySize, entrySize,
                                    (UINT32)header.size(), (UINT32)header.size(),
                                    (UINT32)body.size(), (UINT32)body.size(),
                                    entry->entry_type(),
                                    entry->checksum())
                    + (entry->checksum() != calculated ? usprintf(", invalid, should be %02Xh", calculated) : UString(", valid"))
                    + usprintf("\nVarId: %04Xh\nGuidId: %04Xh\nAttributes: %08Xh (",
                               dataEntry->var_id(),
                               dataEntry->guid_id(),
                               attributes)
                    + evsaAttributesToUString(attributes) + UString(")");
                }
                
                // Add tree item
                model->addItem(entryOffset, Types::EvsaEntry, subtype, name, text, info, header, body, UByteArray(), Fixed, headerIndex);
                
                entryOffset += entrySize;
            }
            
            // Reparse all data variables to detect invalid ones and assign name and test to valid ones
            for (int i = 0; i < model->rowCount(headerIndex); i++) {
                UModelIndex current = headerIndex.model()->index(i, 0, headerIndex);
                
                if (model->subtype(current) == Subtypes::DataEvsaEntry) {
                    UByteArray header = model->header(current);
                    const EVSA_DATA_ENTRY* dataHeader = (const EVSA_DATA_ENTRY*)header.constData();
                    UString guid;
                    if (guidMap.count(dataHeader->GuidId))
                        guid = guidToUString(guidMap[dataHeader->GuidId], false);
                    UString name;
                    if (nameMap.count(dataHeader->VarId))
                        name = nameMap[dataHeader->VarId];
                    
                    // Check for variable validity
                    if (guid.isEmpty() && name.isEmpty()) { // Both name and guid aren't found
                        model->setSubtype(current, Subtypes::InvalidEvsaEntry);
                        model->setName(current, UString("Invalid"));
                        model->setText(current, UString());
                        msg(usprintf("%s: data variable with invalid GuidId and invalid VarId", __FUNCTION__), current);
                    }
                    else if (guid.isEmpty()) { // Guid not found
                        model->setSubtype(current, Subtypes::InvalidEvsaEntry);
                        model->setName(current, UString("Invalid"));
                        model->setText(current, UString());
                        msg(usprintf("%s: data variable with invalid GuidId", __FUNCTION__), current);
                    }
                    else if (name.isEmpty()) { // Name not found
                        model->setSubtype(current, Subtypes::InvalidEvsaEntry);
                        model->setName(current, UString("Invalid"));
                        model->setText(current, UString());
                        msg(usprintf("%s: data variable with invalid VarId", __FUNCTION__), current);
                    }
                    else { // Variable is OK, rename it
                        if (dataHeader->Header.Type == NVRAM_EVSA_ENTRY_TYPE_DATA_INVALID) {
                            model->setSubtype(current, Subtypes::InvalidEvsaEntry);
                            model->setName(current, UString("Invalid"));
                            model->setText(current, UString());
                        }
                        else {
                            model->setName(current, guid);
                            model->setText(current, name);
                            model->addInfo(current, UString("GUID: ") + guid + UString("\nName: ") + name + "\n", false);
                        }
                    }
                }
            }
            
            storeOffset += storeSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        // Phoenix CMDB
        
        // Phoenix SLIC Pubkey/Marker
        
        // Intel uCode
        try {
            // Check data size
            if (volumeBodySize - storeOffset < sizeof(INTEL_MICROCODE_HEADER)) {
                throw 0;
            }
            
            const UINT32 currentUint32 = readUnaligned((const UINT32*)(volumeBody.constData() + storeOffset));
            
            if (currentUint32 != INTEL_MICROCODE_HEADER_VERSION_1) {
                throw 0;
            }
            
            // Check microcode header candidate
            const INTEL_MICROCODE_HEADER* ucodeHeader = (const INTEL_MICROCODE_HEADER*)(volumeBody.constData() + storeOffset);
            if (FALSE == ffsParser->microcodeHeaderValid(ucodeHeader)) {
                throw 0;
            }
            
            // Check size candidate
            if (ucodeHeader->TotalSize == 0) {
                throw 0;
            }
            
            // All checks passed, microcode found
            UByteArray ucode = volumeBody.mid(storeOffset);
            UModelIndex ucodeIndex;
            if (U_SUCCESS != ffsParser->parseIntelMicrocodeHeader(ucode, storeOffset, index, ucodeIndex)) {
                throw 0;
            }
            
            storeOffset += ucodeHeader->TotalSize - 1;
            previousStoreEndOffset = storeOffset + 1;
            continue;
        } catch (...) {
            // Parsing failed, try something else
        }
        
        // Padding
        if (storeOffset < volumeBodySize) {
            outerPadding += volumeBody[storeOffset];
        }
    }
    
    // Add padding at the very end
    if (!outerPadding.isEmpty()) {
        // Add info
        UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
        
        // Check that remaining unparsed bytes are actually empty
        if (outerPadding.count(emptyByte) == outerPadding.size()) {
            // Add tree item
            model->addItem(localOffset + previousStoreEndOffset, Types::FreeSpace, 0, UString("Free space"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
        }
        else {
            // Add tree item
            model->addItem(localOffset + previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
        }
    }

    return U_SUCCESS;
}
#endif // U_ENABLE_NVRAM_PARSING_SUPPORT
