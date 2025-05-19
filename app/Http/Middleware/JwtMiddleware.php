<?php
namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JwtMiddleware 
{
    public function handle($request, Closure $next)
{
    try {
        JWTAuth::parseToken()->authenticate();
    } catch (TokenExpiredException $e) {
        return response()->json([
            'status' => 'error',
            'message' => 'Token expired. Please refresh or log in again.',
            'code' => 'token_expired',
        ], 401);
    } catch (JWTException $e) {
        return response()->json([
            'status' => 'error',
            'message' => 'Invalid token. Please log in again.',
        ], 401);
    }

    return $next($request);
}
}
