#pragma once

#include "crow/http_request.h"
#include "crow/http_response.h"
#include "crow/routing.h"
#include "crow/middleware.h"

namespace crow
{
    class SimpleApp
    {
    public:
        void use(std::function<void(const request&, response&, std::function<void()>)> middleware)
        {
            // Middleware implementation
        }
        
        void port(int port)
        {
            port_ = port;
        }
        
        void run()
        {
            // Server run implementation
        }
        
    private:
        int port_ = 8080;
    };
}
