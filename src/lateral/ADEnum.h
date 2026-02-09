#pragma once
#include <string>

namespace lateral {

/**
 * ADEnum: Active Directory Enumeration.
 * Provides features to discover domain info, DCs, users, groups and computers.
 */
class ADEnum {
public:
    static std::string GetDomainInfo();
    static std::string EnumerateComputers();
    static std::string EnumerateUsers();
    static std::string EnumerateGroups();
    static std::string EnumerateDomainAdmins();
};

} // namespace lateral
