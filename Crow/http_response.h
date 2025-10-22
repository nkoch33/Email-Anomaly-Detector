#pragma once

#include <string>
#include <map>

namespace crow
{
    class response
    {
    public:
        int code = 200;
        std::string body;
        std::map<std::string, std::string> headers;
        
        void add_header(const std::string& key, const std::string& value)
        {
            headers[key] = value;
        }
    };
}
