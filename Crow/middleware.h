#pragma once

#include <functional>

namespace crow
{
    class request;
    class response;
    
    using middleware_handler = std::function<void(const request&, response&, std::function<void()>)>;
}
