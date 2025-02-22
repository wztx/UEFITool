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
#include "generated/edk2_vss.h"
#include "generated/phoenix_vss2.h"

USTATUS NvramParser::parseNvarStore(const UModelIndex & index)
{
    // Sanity check
    if (!index.isValid())
        return U_INVALID_PARAMETER;

    UByteArray nvar = model->body(index);

    // Nothing to parse in an empty store
    if (nvar.isEmpty())
        return U_SUCCESS;

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

                if ((UINT32)padding.count(0xFF) == unparsedSize) { // Free space
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
            pdata.emptyByte = 0xFF;
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

USTATUS NvramParser::parseNvramVolumeBody(const UModelIndex & index)
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
        bool storeFound = false;
        // Try parsing as VSS store
        try {
            UByteArray vss = volumeBody.mid(storeOffset);
            umemstream is(vss.constData(), vss.size());
            kaitai::kstream ks(&is);
            edk2_vss_t parsed(&ks);

            // VSS store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }

            // Construct header and body
            UByteArray header = vss.left(parsed.len_vss_store_header());
            UByteArray body = vss.mid(header.size(), parsed.vss_size() - header.size());
            
            // Add info
            UString name;
            if (parsed.signature() == NVRAM_APPLE_SVS_STORE_SIGNATURE) {
                name = UString("SVS store");
            }
            else if (parsed.signature() == NVRAM_APPLE_NSS_STORE_SIGNATURE) {
                name = UString("NSS store");
            }
            else {
                name = UString("VSS store");
            }
            UString info = usprintf("Signature: %Xh (", parsed.signature()) + fourCC(parsed.signature()) + UString(")\n");
            
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nFormat: %02Xh\nState: %02Xh\nReserved: %02Xh\nReserved1: %04Xh",
                            parsed.vss_size() , parsed.vss_size(),
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.format(),
                            parsed.state(),
                            parsed.reserved(),
                            parsed.reserved1());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::VssStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            UINT32 vssVariableOffset = storeOffset + parsed.len_vss_store_header();
            for (const auto & variable : *parsed.body()->variables()) {
                UINT8 subtype;
                UString text;
                info.clear();
                name.clear();
                
                // This is thew terminating entry, needs special processing
                if (variable->_is_null_signature_last()) {
                    // Add free space or padding after all variables, if needed
                    if (vssVariableOffset < parsed.vss_size()) {
                        UByteArray freeSpace = vss.mid(vssVariableOffset, parsed.vss_size() - vssVariableOffset);
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
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else if (variable->is_auth()) { // Authenticated
                    subtype = Subtypes::AuthVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_auth_header() + variable->len_name_auth());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data_auth());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name_auth().c_str());
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else if (!variable->_is_null_apple_data_crc32()) { // Apple CRC32
                    subtype = Subtypes::AppleVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_apple_header() + variable->len_name());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else { // Standard
                    subtype = Subtypes::StandardVssEntry;
                    header = vss.mid(vssVariableOffset, variable->len_standard_header() + variable->len_name());
                    body = vss.mid(vssVariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
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
            
            storeFound = true;
            storeOffset += parsed.vss_size();
            previousStoreEndOffset = storeOffset;
        } catch (...) {
           // Parsing failed, try something else
        }

        // VSS2
        try {
            UByteArray vss2 = volumeBody.mid(storeOffset);
            umemstream is(vss2.constData(), vss2.size());
            kaitai::kstream ks(&is);
            phoenix_vss2_t parsed(&ks);

            // VSS2 store at current offset parsed correctly
            // Check if we need to add a padding before it
            if (!outerPadding.isEmpty()) {
                UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
                model->addItem(previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
                outerPadding.clear();
            }

            // Construct header and body
            UByteArray header = vss2.left(parsed.len_vss2_store_header());
            UByteArray body = vss2.mid(header.size(), parsed.vss2_size() - header.size());
            
            // Add info
            UString name = UString("VSS2 store");
            UString info;
            if (parsed.signature() == NVRAM_VSS2_AUTH_VAR_KEY_DATABASE_GUID_PART1) {
                info = UString("Signature: AAF32C78-947B-439A-A180-2E144EC37792\n");
            }
            else {
                info = UString("Signature: DDCF3617-3275-4164-98B6-FE85707FFE7D\n");
            }
            
            info += usprintf("Full size: %Xh (%u)\nHeader size: %Xh (%u)\nBody size: %Xh (%u)\nFormat: %02Xh\nState: %02Xh\nReserved: %02Xh\nReserved1: %04Xh",
                            parsed.vss2_size() , parsed.vss2_size(),
                            (UINT32)header.size(), (UINT32)header.size(),
                            (UINT32)body.size(), (UINT32)body.size(),
                            parsed.format(),
                            parsed.state(),
                            parsed.reserved(),
                            parsed.reserved1());
            
            // Add header tree item
            UModelIndex headerIndex = model->addItem(localOffset + storeOffset, Types::VssStore, 0, name, UString(), info, header, body, UByteArray(), Fixed, index);
            
            UINT32 vss2VariableOffset = storeOffset + parsed.len_vss2_store_header();
            for (const auto & variable : *parsed.body()->variables()) {
                UINT8 subtype;
                UString text;
                info.clear();
                name.clear();
                
                // This is thew terminating entry, needs special processing
                if (variable->_is_null_signature_last()) {
                    // Add free space or padding after all variables, if needed
                    if (vss2VariableOffset < parsed.vss2_size()) {
                        UByteArray freeSpace = vss2.mid(vss2VariableOffset, parsed.vss2_size() - vss2VariableOffset);
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
                if (variable->is_auth()) { // Authenticated
                    subtype = Subtypes::AuthVssEntry;
                    header = vss2.mid(vss2VariableOffset, variable->len_auth_header() + variable->len_name_auth());
                    body = vss2.mid(vss2VariableOffset + header.size(), variable->len_data_auth());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name_auth().c_str());
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
                }
                else { // Standard
                    subtype = Subtypes::StandardVssEntry;
                    header = vss2.mid(vss2VariableOffset, variable->len_standard_header() + variable->len_name());
                    body = vss2.mid(vss2VariableOffset + header.size(), variable->len_data());
                    variableSize = (UINT32)(header.size() + body.size());
                    const EFI_GUID variableGuid = readUnaligned((const EFI_GUID*)(variable->vendor_guid().c_str()));
                    name = guidToUString(variableGuid);
                    text = uFromUcs2(variable->name().c_str());
                    info += UString("Variable GUID: ") + guidToUString(variableGuid, false) + "\n";
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
                + (variable->attributes()->append_write() << 6);
                
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
                
                vss2VariableOffset += variableSize;
            }
            
            storeFound = true;
            storeOffset += parsed.vss2_size();
            previousStoreEndOffset = storeOffset;
        } catch (...) {
           // Parsing failed, try something else
        }
        
        // FDC
        
        // EVSA
        
        // FTW
        
        // Apple Fsys/Gaid
        
        // Phoenix FlashMap
        // Phoenix CMDB
        // Phoenix SLIC Pubkey/Marker
        // Intel uCode
        
        // Padding
        outerPadding.append(volumeBody.at(storeOffset));
    }
    
    // Add padding at the very end
    if (!outerPadding.isEmpty()) {
        // Add info
        UString info = usprintf("Full size: %Xh (%u)", (UINT32)outerPadding.size(), (UINT32)outerPadding.size());
        // Add tree item
        model->addItem(localOffset + previousStoreEndOffset, Types::Padding, getPaddingType(outerPadding), UString("Padding"), UString(), info, UByteArray(), outerPadding, UByteArray(), Fixed, index);
    }

    return U_SUCCESS;
}
#endif // U_ENABLE_NVRAM_PARSING_SUPPORT
