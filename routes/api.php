<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

Route::middleware('api')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);

    Route::middleware('jwt')->group(function () {
        Route::get('/user', [AuthController::class, 'getUser']);
        Route::put('/user', [AuthController::class, 'updateUser']);
        Route::post('auth/refresh', [AuthController::class, 'refresh']);
        Route::post('/logout', [AuthController::class, 'logout']);
    });
});

Route::get('/test', function () { // Keep this for testing
    return response()->json(['message' => 'Test endpoint from API']);
});
