<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * These middleware are run during every request to your application.
     *
     * @var array
     */
    // 全局中间件，最先调用
    protected $middleware = [

        // 检测是否应用是否进入’维护模式‘
        \Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode::class,

        // 检测请求的数据是否过大
        \Illuminate\Foundation\Http\Middleware\ValidatePostSize::class,

        // 对提交的请求参数进行PHP函数'trim()'处理
        \App\Http\Middleware\TrimStrings::class,

        // 将提交请求参数中空子串转换为null
        \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,

        // 修正代理服务器后的服务器参数
        \App\Http\Middleware\TrustProxies::class,
    ];

    /**
     * The application's route middleware groups.
     *
     * @var array
     */
    // 定义中间件组
    protected $middlewareGroups = [

        // Web中间件组，应用于routes/web.php路由文件
        'web' => [
            // Cookie加密解密
            \App\Http\Middleware\EncryptCookies::class,

            // 将Cookie添加到响应中
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,

            // 开启会话
            \Illuminate\Session\Middleware\StartSession::class,

            // 认证用户，此中间件以后Auth类才能生效
            \Illuminate\Session\Middleware\AuthenticateSession::class,

            // 将系统的错误数据注入到视图变量$errors中
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,

            // 检验CSRF,防止跨站请求伪造的安全威胁
            \App\Http\Middleware\VerifyCsrfToken::class,

            // 处理路由绑定
            \Illuminate\Routing\Middleware\SubstituteBindings::class,

            // 记录用户最后活跃时间
            \App\Http\Middleware\RecordLastActiveTime::class,
        ],

        'api' => [
            'throttle:60,1',
            'bindings',
        ],
    ];

    /**
     * The application's route middleware.
     *
     * These middleware may be assigned to groups or used individually.
     *
     * @var array
     */
    protected $routeMiddleware = [
        'auth' => \Illuminate\Auth\Middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
        'bindings' => \Illuminate\Routing\Middleware\SubstituteBindings::class,
        'can' => \Illuminate\Auth\Middleware\Authorize::class,
        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
        'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
    ];
}
