<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
{
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|between:2,100',
        'email' => 'required|string|email|max:100|unique:users',
        'password' => 'required|string|min:6',
    ]);

    if ($validator->fails()) {
        return response()->json($validator->errors()->toJson(), 400);
    }

    $user = User::create(array_merge(
        $validator->validated(),
        ['password' => Hash::make($request->password)]
    ));

    return response()->json([
        'message' => 'User successfully registered',
        'user' => $user,
    ], 201);
}

    public function login(Request $request)
{
    $credentials = $request->only('email', 'password');

    if (!$token = auth()->attempt($credentials)) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    $refreshToken = $this->createRefreshToken(auth()->user());
    
    return $this->respondWithTokens($token, $refreshToken);
}

    public function logout(): JsonResponse
    {
        auth()->logout();
        return response()->json(['message' => 'User successfully signed out']);
    }

    public function getUser(): JsonResponse
    {
        return response()->json(auth()->user());
    }

    public function updateUser(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'string|between:2,100',
            'email' => 'string|email|max:100|unique:users,email,' . auth()->id(),
            'password' => 'string|min:6|nullable',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = auth()->user();
        $userData = $validator->validated();

        if (isset($userData['password'])) {
            $userData['password'] = Hash::make($userData['password']);
        }

        $user->update($userData);

        return response()->json([
            'message' => 'User successfully updated',
            'user' => $user,
        ]);
    }

    public function refresh()
{
    try {
        $newToken = JWTAuth::parseToken()->refresh();
        return response()->json([
            'status' => 'success',
            'token' => $newToken,
            'expires_in' => JWTAuth::factory()->getTTL() * 60,
        ]);
    } catch (JWTException $e) {
        return response()->json([
            'status' => 'error',
            'message' => 'Failed to refresh token. Please log in again.',
        ], 401);
    }
}


    protected function createRefreshToken($user)
{
    $refreshToken = JWTAuth::customClaims([
        'exp' => now()->addDays(30)->timestamp, // 30-day expiry
        'is_refresh_token' => true
    ])->fromUser($user);

    return $refreshToken;
}

protected function respondWithTokens($token, $refreshToken)
{
    return response()->json([
        'access_token' => $token,
        'token_type' => 'bearer',
        'expires_in' => auth()->factory()->getTTL() * 60,
        'refresh_token' => $refreshToken
    ]);
}
}