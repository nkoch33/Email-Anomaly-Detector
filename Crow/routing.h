#pragma once

#include <functional>
#include <string>

namespace crow
{
    class SimpleApp;
    
    template<typename T>
    class route
    {
    public:
        route(T&& handler) : handler_(std::forward<T>(handler)) {}
        
        T handler_;
    };
    
    template<typename T>
    route<T> make_route(T&& handler)
    {
        return route<T>(std::forward<T>(handler));
    }
}

#define CROW_ROUTE(app, rule) \
    app.route(rule, make_route([&](const crow::request& req) -> crow::response { \
        return crow::response(200, "Route handler"); \
    }))
