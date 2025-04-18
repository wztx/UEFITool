#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "../kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>
#include <vector>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class edk2_vss_t : public kaitai::kstruct {

public:
    class vss_store_body_t;
    class vss_variable_attributes_t;
    class vss_variable_t;

    edk2_vss_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, edk2_vss_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~edk2_vss_t();

    class vss_store_body_t : public kaitai::kstruct {

    public:

        vss_store_body_t(kaitai::kstream* p__io, edk2_vss_t* p__parent = nullptr, edk2_vss_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~vss_store_body_t();

    private:
        std::unique_ptr<std::vector<std::unique_ptr<vss_variable_t>>> m_variables;
        edk2_vss_t* m__root;
        edk2_vss_t* m__parent;

    public:
        std::vector<std::unique_ptr<vss_variable_t>>* variables() const { return m_variables.get(); }
        edk2_vss_t* _root() const { return m__root; }
        edk2_vss_t* _parent() const { return m__parent; }
    };

    class vss_variable_attributes_t : public kaitai::kstruct {

    public:

        vss_variable_attributes_t(kaitai::kstream* p__io, edk2_vss_t::vss_variable_t* p__parent = nullptr, edk2_vss_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~vss_variable_attributes_t();

    private:
        bool m_non_volatile;
        bool m_boot_service;
        bool m_runtime;
        bool m_hw_error_record;
        bool m_auth_write;
        bool m_time_based_auth;
        bool m_append_write;
        uint64_t m_reserved;
        bool m_apple_data_checksum;
        edk2_vss_t* m__root;
        edk2_vss_t::vss_variable_t* m__parent;

    public:
        bool non_volatile() const { return m_non_volatile; }
        bool boot_service() const { return m_boot_service; }
        bool runtime() const { return m_runtime; }
        bool hw_error_record() const { return m_hw_error_record; }
        bool auth_write() const { return m_auth_write; }
        bool time_based_auth() const { return m_time_based_auth; }
        bool append_write() const { return m_append_write; }
        uint64_t reserved() const { return m_reserved; }
        bool apple_data_checksum() const { return m_apple_data_checksum; }
        edk2_vss_t* _root() const { return m__root; }
        edk2_vss_t::vss_variable_t* _parent() const { return m__parent; }
    };

    class vss_variable_t : public kaitai::kstruct {

    public:

        vss_variable_t(kaitai::kstream* p__io, edk2_vss_t::vss_store_body_t* p__parent = nullptr, edk2_vss_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~vss_variable_t();

    private:
        bool f_is_auth;
        bool m_is_auth;

    public:
        bool is_auth();

    private:
        bool f_len_standard_header;
        int8_t m_len_standard_header;

    public:
        int8_t len_standard_header();

    private:
        bool f_is_intel_legacy;
        bool m_is_intel_legacy;

    public:
        bool is_intel_legacy();

    private:
        bool f_len_auth_header;
        int8_t m_len_auth_header;

    public:
        int8_t len_auth_header();

    private:
        bool f_len_apple_header;
        int8_t m_len_apple_header;

    public:
        int8_t len_apple_header();

    private:
        bool f_len_intel_legacy_header;
        int8_t m_len_intel_legacy_header;

    public:
        int8_t len_intel_legacy_header();

    private:
        bool f_is_valid;
        bool m_is_valid;

    public:
        bool is_valid();

    private:
        uint8_t m_signature_first;
        uint8_t m_signature_last;
        bool n_signature_last;

    public:
        bool _is_null_signature_last() { signature_last(); return n_signature_last; };

    private:
        uint8_t m_state;
        bool n_state;

    public:
        bool _is_null_state() { state(); return n_state; };

    private:
        uint8_t m_reserved;
        bool n_reserved;

    public:
        bool _is_null_reserved() { reserved(); return n_reserved; };

    private:
        std::unique_ptr<vss_variable_attributes_t> m_attributes;
        bool n_attributes;

    public:
        bool _is_null_attributes() { attributes(); return n_attributes; };

    private:
        uint32_t m_len_total;
        bool n_len_total;

    public:
        bool _is_null_len_total() { len_total(); return n_len_total; };

    private:
        uint32_t m_len_name;
        bool n_len_name;

    public:
        bool _is_null_len_name() { len_name(); return n_len_name; };

    private:
        uint32_t m_len_data;
        bool n_len_data;

    public:
        bool _is_null_len_data() { len_data(); return n_len_data; };

    private:
        std::string m_timestamp;
        bool n_timestamp;

    public:
        bool _is_null_timestamp() { timestamp(); return n_timestamp; };

    private:
        uint32_t m_pubkey_index;
        bool n_pubkey_index;

    public:
        bool _is_null_pubkey_index() { pubkey_index(); return n_pubkey_index; };

    private:
        uint32_t m_len_name_auth;
        bool n_len_name_auth;

    public:
        bool _is_null_len_name_auth() { len_name_auth(); return n_len_name_auth; };

    private:
        uint32_t m_len_data_auth;
        bool n_len_data_auth;

    public:
        bool _is_null_len_data_auth() { len_data_auth(); return n_len_data_auth; };

    private:
        std::string m_vendor_guid;
        bool n_vendor_guid;

    public:
        bool _is_null_vendor_guid() { vendor_guid(); return n_vendor_guid; };

    private:
        std::string m_name_auth;
        bool n_name_auth;

    public:
        bool _is_null_name_auth() { name_auth(); return n_name_auth; };

    private:
        std::string m_data_auth;
        bool n_data_auth;

    public:
        bool _is_null_data_auth() { data_auth(); return n_data_auth; };

    private:
        uint32_t m_apple_data_crc32;
        bool n_apple_data_crc32;

    public:
        bool _is_null_apple_data_crc32() { apple_data_crc32(); return n_apple_data_crc32; };

    private:
        std::string m_intel_legacy_data;
        bool n_intel_legacy_data;

    public:
        bool _is_null_intel_legacy_data() { intel_legacy_data(); return n_intel_legacy_data; };

    private:
        std::string m_name;
        bool n_name;

    public:
        bool _is_null_name() { name(); return n_name; };

    private:
        std::string m_data;
        bool n_data;

    public:
        bool _is_null_data() { data(); return n_data; };

    private:
        edk2_vss_t* m__root;
        edk2_vss_t::vss_store_body_t* m__parent;

    public:
        uint8_t signature_first() const { return m_signature_first; }
        uint8_t signature_last() const { return m_signature_last; }
        uint8_t state() const { return m_state; }
        uint8_t reserved() const { return m_reserved; }
        vss_variable_attributes_t* attributes() const { return m_attributes.get(); }
        uint32_t len_total() const { return m_len_total; }
        uint32_t len_name() const { return m_len_name; }
        uint32_t len_data() const { return m_len_data; }
        std::string timestamp() const { return m_timestamp; }
        uint32_t pubkey_index() const { return m_pubkey_index; }
        uint32_t len_name_auth() const { return m_len_name_auth; }
        uint32_t len_data_auth() const { return m_len_data_auth; }
        std::string vendor_guid() const { return m_vendor_guid; }
        std::string name_auth() const { return m_name_auth; }
        std::string data_auth() const { return m_data_auth; }
        uint32_t apple_data_crc32() const { return m_apple_data_crc32; }
        std::string intel_legacy_data() const { return m_intel_legacy_data; }
        std::string name() const { return m_name; }
        std::string data() const { return m_data; }
        edk2_vss_t* _root() const { return m__root; }
        edk2_vss_t::vss_store_body_t* _parent() const { return m__parent; }
    };

private:
    bool f_len_vss_store_header;
    int8_t m_len_vss_store_header;

public:
    int8_t len_vss_store_header();

private:
    uint32_t m_signature;
    uint32_t m_vss_size;
    uint8_t m_format;
    uint8_t m_state;
    uint16_t m_reserved;
    uint32_t m_reserved1;
    std::unique_ptr<vss_store_body_t> m_body;
    edk2_vss_t* m__root;
    kaitai::kstruct* m__parent;
    std::string m__raw_body;
    std::unique_ptr<kaitai::kstream> m__io__raw_body;

public:
    uint32_t signature() const { return m_signature; }
    uint32_t vss_size() const { return m_vss_size; }
    uint8_t format() const { return m_format; }
    uint8_t state() const { return m_state; }
    uint16_t reserved() const { return m_reserved; }
    uint32_t reserved1() const { return m_reserved1; }
    vss_store_body_t* body() const { return m_body.get(); }
    edk2_vss_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
    std::string _raw_body() const { return m__raw_body; }
    kaitai::kstream* _io__raw_body() const { return m__io__raw_body.get(); }
};
