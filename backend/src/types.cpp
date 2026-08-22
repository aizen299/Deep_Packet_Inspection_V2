#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Matches a dotted pattern only at a domain-label boundary: the host must equal
// it, or end with "." + it. A plain substring search silently misattributes
// traffic -- `find("x.com")` hits inside "netflix.com", and because the Twitter
// branch is tested before the Netflix one, every Netflix flow was reported as
// Twitter/X. `t.co` has the same problem inside "sport.com".
//
// Brand tokens below ("google", "netflix", ...) intentionally stay substring
// matches, since they need to catch subdomains like googlevideo.com.
static bool matchesDomain(const std::string& host, const std::string& pattern) {
    if (host.size() == pattern.size()) return host == pattern;
    if (host.size() < pattern.size() + 1) return false;
    const size_t offset = host.size() - pattern.size();
    return host[offset - 1] == '.' &&
           host.compare(offset, pattern.size(), pattern) == 0;
}

AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        matchesDomain(lower_sni, "youtu.be") ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        matchesDomain(lower_sni, "fb.com") ||
        lower_sni.find("fbsbx") != std::string::npos ||
        matchesDomain(lower_sni, "meta.com")) {
        return AppType::FACEBOOK;
    }
    
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    if (lower_sni.find("whatsapp") != std::string::npos ||
        matchesDomain(lower_sni, "wa.me")) {
        return AppType::WHATSAPP;
    }
    
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        matchesDomain(lower_sni, "x.com") ||
        matchesDomain(lower_sni, "t.co")) {
        return AppType::TWITTER;
    }
    
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    if (lower_sni.find("microsoft") != std::string::npos ||
        matchesDomain(lower_sni, "msn.com") ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        matchesDomain(lower_sni, "live.com") ||
        lower_sni.find("outlook") != std::string::npos ||
        lower_sni.find("bing") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos) {
        return AppType::APPLE;
    }
    
    if (lower_sni.find("telegram") != std::string::npos ||
        matchesDomain(lower_sni, "t.me")) {
        return AppType::TELEGRAM;
    }
    
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        matchesDomain(lower_sni, "musical.ly") ||
        lower_sni.find("bytedance") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    if (lower_sni.find("spotify") != std::string::npos ||
        matchesDomain(lower_sni, "scdn.co")) {
        return AppType::SPOTIFY;
    }
    
    if (lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos) {
        return AppType::GITHUB;
    }
    
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cf-") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    return AppType::HTTPS;
}

}
