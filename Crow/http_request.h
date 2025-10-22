#pragma once

#include <string>
#include <map>

namespace crow
{
    class request
    {
    public:
        std::string body;
        
        std::string get_header_value(const std::string& key) const
        {
            auto it = headers.find(key);
            return it != headers.end() ? it->second : "";
        }
        
        std::map<std::string, std::string> headers;
    };
}
