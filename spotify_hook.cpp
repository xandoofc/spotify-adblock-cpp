// Shared library to hook CEF functions and block ads with JPL-inspired safety
#include <dlfcn.h>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>

// CEF headers (assumed available via system or project includes)
extern "C" {
    typedef struct _cef_string_utf16_t {
        char16_t* str;
        size_t length;
        void (*dtor)(char16_t* str);
    } cef_string_t;

    typedef cef_string_t* cef_string_userfree_t;

    typedef struct _cef_request_t cef_request_t;
    typedef struct _cef_urlrequest_client_t cef_urlrequest_client_t;
    typedef struct _cef_request_context_t cef_request_context_t;
    typedef struct _cef_urlrequest_t cef_urlrequest_t;

    typedef cef_urlrequest_t* (*cef_urlrequest_create_t)(cef_request_t*, cef_urlrequest_client_t*, cef_request_context_t*);

    struct _cef_request_t {
        void* base;
        int (*is_read_only)(cef_request_t*);
        cef_string_userfree_t (*get_url)(cef_request_t*);
        cef_string_userfree_t (*get_method)(cef_request_t*);
    };

    void cef_string_userfree_utf16_free(cef_string_t* str);
    cef_urlrequest_t* cef_urlrequest_create(cef_request_t* request, cef_urlrequest_client_t* client, cef_request_context_t* request_context);
}

// URL classification structure
struct UrlClassification {
    bool is_discord_rpc;
    bool is_gabo;
    bool is_dealer;
    bool is_ad_related;
};

// Convert UTF-16 to UTF-8
std::string utf16_to_utf8(const char16_t* utf16, size_t length) {
    std::string utf8;
    for (size_t i = 0; i < length; ++i) {
        char16_t c = utf16[i];
        if (c <= 0x7F) {
            utf8.push_back(static_cast<char>(c));
        } else if (c <= 0x7FF) {
            utf8.push_back(static_cast<char>(0xC0 | (c >> 6)));
            utf8.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            utf8.push_back(static_cast<char>(0xE0 | (c >> 12)));
            utf8.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return utf8;
}

// Convert CEF UTF-16 string to std::string with safety checks
std::string cef_string_to_string(const cef_string_t* cef_str) {
    std::ofstream log("/tmp/spotify_hook.log", std::ios::app);
    // Double null check for radiation-hardened safety
    bool is_null = !cef_str;
    bool is_really_null = !cef_str;
    if (is_null || is_really_null) {
        log << "cef_string_to_string: Null string pointer\n";
        log.close();
        return "";
    }
    if (!cef_str->str || cef_str->length == 0) {
        log << "cef_string_to_string: Invalid or empty string (str=" << std::hex << (void*)cef_str->str << ", length=" << std::dec << cef_str->length << ")\n";
        log.close();
        return "";
    }
    std::string result = utf16_to_utf8(cef_str->str, cef_str->length);
    log << "cef_string_to_string: Converted string: " << result << " (str=" << std::hex << (void*)cef_str->str << ", length=" << std::dec << cef_str->length << ")\n";
    log.close();
    return result;
}

// Classify URL based on ad-related patterns
UrlClassification classify_url(const std::string& url) {
    UrlClassification classification = {false, false, false, false};

    if (url.find("discord") != std::string::npos ||
        url.find("discordapp") != std::string::npos ||
        url.find("presence") != std::string::npos ||
        url.find("/presence2/") != std::string::npos ||
        url.find("connect-state") != std::string::npos ||
        url.find("rpc") != std::string::npos) {
        classification.is_discord_rpc = true;
    }
    if (url.find("gabo-receiver-service") != std::string::npos) {
        classification.is_gabo = true;
    }
    if (url.find("dealer") != std::string::npos) {
        classification.is_dealer = true;
    }
    if (url.find("/ads/") != std::string::npos ||
        url.find("ad-logic") != std::string::npos ||
        url.find("doubleclick") != std::string::npos ||
        url.find("googleads") != std::string::npos ||
        url.find("adswizz") != std::string::npos ||
        url.find("analytics") != std::string::npos ||
        url.find("sponsor") != std::string::npos ||
        url.find("partnership") != std::string::npos ||
        url.find("brand") != std::string::npos ||
        url.find("whatsapp") != std::string::npos ||
        url.find("hpto") != std::string::npos ||
        url.find("promoted") != std::string::npos ||
        url.find("takeover") != std::string::npos ||
        (url.find("clientsettings") != std::string::npos && url.find("api") != std::string::npos) ||
        (url.find("track") != std::string::npos && url.find("event") != std::string::npos) ||
        (url.find("ads") != std::string::npos && url.find("gabo") == std::string::npos)) {
        classification.is_ad_related = true;
    }
    return classification;
}

// Denylist for explicit blocking
static const std::vector<std::regex> denylist = {
    std::regex("https://spclient\\.wg\\.spotify\\.com/ads/.*")
};

// Original CEF function pointers
static cef_urlrequest_create_t original_cef_urlrequest_create = nullptr;
static void (*original_cef_string_userfree_utf16_free)(cef_string_t*) = nullptr;

// Initialize hooks
void initialize_hooks() {
    std::ofstream log("/tmp/spotify_hook.log", std::ios::app);
    log << "Initializing hooks\n";

    if (!original_cef_urlrequest_create) {
        original_cef_urlrequest_create = (cef_urlrequest_create_t)dlsym(RTLD_NEXT, "cef_urlrequest_create");
        if (!original_cef_urlrequest_create) {
            log << "Failed to resolve cef_urlrequest_create\n";
        } else {
            log << "Resolved cef_urlrequest_create at " << std::hex << (void*)original_cef_urlrequest_create << "\n";
        }
    }

    if (!original_cef_string_userfree_utf16_free) {
        original_cef_string_userfree_utf16_free = (void (*)(cef_string_t*))dlsym(RTLD_NEXT, "cef_string_userfree_utf16_free");
        if (!original_cef_string_userfree_utf16_free) {
            log << "Failed to resolve cef_string_userfree_utf16_free\n";
        } else {
            log << "Resolved cef_string_userfree_utf16_free at " << std::hex << (void*)original_cef_string_userfree_utf16_free << "\n";
        }
    }

    log.close();
}

// Hooked CEF string free function
extern "C" void cef_string_userfree_utf16_free(cef_string_t* str) {
    std::ofstream log("/tmp/spotify_hook.log", std::ios::app);
    log << "cef_string_userfree_utf16_free called with str=" << std::hex << (void*)str << "\n";

    // Double null check for radiation-hardened safety
    bool is_null = !str;
    bool is_really_null = !str;
    if (is_null || is_really_null) {
        log << "Null pointer in cef_string_userfree_utf16_free, skipping\n";
        log.close();
        return;
    }

    if (!original_cef_string_userfree_utf16_free) {
        initialize_hooks();
        if (!original_cef_string_userfree_utf16_free) {
            log << "Failed to resolve original_cef_string_userfree_utf16_free\n";
            log.close();
            return;
        }
    }

    original_cef_string_userfree_utf16_free(str);
    log << "cef_string_userfree_utf16_free completed\n";
    log.close();
}

// Hooked CEF function
extern "C" cef_urlrequest_t* cef_urlrequest_create(cef_request_t* request, cef_urlrequest_client_t* client, cef_request_context_t* request_context) {
    std::ofstream log("/tmp/spotify_hook.log", std::ios::app);
    log << "cef_urlrequest_create called with request=" << std::hex << (void*)request << ", client=" << (void*)client << ", context=" << (void*)request_context << "\n";

    // Initialize hooks if not already done
    if (!original_cef_urlrequest_create) {
        initialize_hooks();
        if (!original_cef_urlrequest_create) {
            log << "Failed to resolve original_cef_urlrequest_create, bypassing hook\n";
            log.close();
            return nullptr;
        }
    }

    // Validate request with double null check
    bool is_null = !request || !request->base || !request->get_url || !request->get_method;
    bool is_really_null = !request || !request->base || !request->get_url || !request->get_method;
    if (is_null || is_really_null) {
        log << "Invalid request or function pointers (request=" << std::hex << (void*)request << ", base=" << (request ? (void*)request->base : nullptr) << ", get_url=" << (request ? (void*)request->get_url : nullptr) << ", get_method=" << (request ? (void*)request->get_method : nullptr) << ")\n";
        log.close();
        return original_cef_urlrequest_create(request, client, request_context);
    }

    // Test is_read_only to validate request object
    bool is_read_only_valid = false;
    int read_only_result = 0;
    if (request->is_read_only) {
        read_only_result = request->is_read_only(request);
        is_read_only_valid = true;
        log << "is_read_only returned " << read_only_result << "\n";
    } else {
        log << "is_read_only function pointer is null\n";
    }

    // Extract URL with additional validation
    cef_string_userfree_t url_cef = nullptr;
    std::string url;
    bool url_valid = false;
    if (request->get_url) {
        url_cef = request->get_url(request);
        log << "get_url returned url_cef=" << std::hex << (void*)url_cef << "\n";
        if (url_cef && url_cef->str && url_cef->length > 0) {
            url = cef_string_to_string(url_cef);
            url_valid = true;
        } else {
            log << "Invalid URL string (url_cef=" << std::hex << (void*)url_cef << ", str=" << (url_cef ? (void*)url_cef->str : nullptr) << ", length=" << (url_cef ? url_cef->length : 0) << ")\n";
        }
        if (url_cef) {
            cef_string_userfree_utf16_free(url_cef);
            url_cef = nullptr; // Prevent double-free
        }
    } else {
        log << "get_url function pointer is null\n";
    }
    log << "URL: " << (url_valid ? url : "<invalid or null>") << "\n";

    // Extract method with additional validation
    cef_string_userfree_t method_cef = nullptr;
    std::string method;
    bool method_valid = false;
    if (request->get_method) {
        method_cef = request->get_method(request);
        log << "get_method returned method_cef=" << std::hex << (void*)method_cef << "\n";
        if (method_cef && method_cef->str && method_cef->length > 0) {
            method = cef_string_to_string(method_cef);
            method_valid = true;
        } else {
            log << "Invalid method string (method_cef=" << std::hex << (void*)method_cef << ", str=" << (method_cef ? (void*)method_cef->str : nullptr) << ", length=" << (url_cef ? method_cef->length : 0) << ")\n";
        }
        if (method_cef) {
            cef_string_userfree_utf16_free(method_cef);
            method_cef = nullptr; // Prevent double-free
        }
    } else {
        log << "get_method function pointer is null\n";
    }
    log << "Method: " << (method_valid ? method : "<invalid or null>") << "\n";

    // Fallback: bypass hook if request is problematic
    if (!url_valid || !is_read_only_valid) {
        log << "Bypassing hook due to invalid URL or read-only check (url_valid=" << url_valid << ", is_read_only_valid=" << is_read_only_valid << ")\n";
        log.close();
        return original_cef_urlrequest_create(request, client, request_context);
    }

    // Classify URL
    UrlClassification classification = classify_url(url);
    log << "Classification: discord=" << classification.is_discord_rpc
        << ", gabo=" << classification.is_gabo
        << ", dealer=" << classification.is_dealer
        << ", ad_related=" << classification.is_ad_related << "\n";

    // Decision logic
    if (classification.is_discord_rpc || classification.is_gabo || classification.is_dealer) {
        log << "Allowing request (discord/gabo/dealer)\n";
        log.close();
        return original_cef_urlrequest_create(request, client, request_context);
    }
    if (std::any_of(denylist.begin(), denylist.end(), [&url](const std::regex& re) { return std::regex_match(url, re); })) {
        log << "Blocking request (denylist match)\n";
        log.close();
        return nullptr; // Block due to denylist
    }
    if (classification.is_ad_related) {
        log << "Blocking request (ad-related)\n";
        log.close();
        return nullptr; // Block ad-related request
    }

    // Allow non-ad requests
    log << "Allowing non-ad request\n";
    log.close();
    return original_cef_urlrequest_create(request, client, request_context);
}