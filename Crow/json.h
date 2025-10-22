#pragma once

#include <string>
#include <map>
#include <vector>

namespace crow
{
    namespace json
    {
        class wvalue
        {
        public:
            wvalue() = default;
            wvalue(const std::string& s) : value_(s) {}
            wvalue(int i) : value_(std::to_string(i)) {}
            wvalue(double d) : value_(std::to_string(d)) {}
            
            wvalue(std::initializer_list<std::pair<std::string, wvalue>> list)
            {
                for (const auto& pair : list)
                {
                    // Implementation for object creation
                }
            }
            
            std::string dump() const
            {
                return value_;
            }
            
            std::string s() const
            {
                return value_;
            }
            
        private:
            std::string value_;
        };
        
        wvalue load(const std::string& json_str)
        {
            return wvalue(json_str);
        }
    }
}
