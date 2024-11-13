<?php



namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    // Register new user
    public function register(Request $request)
    {
        // Validate the input
        $request->validate([
            'name' => 'required|string|min:5|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        // Create new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Return a success message
        return response()->json(['message' => 'User registered successfully.'], 201);
    }

    // Login and issue API token
    public function login(Request $request)
    {
        // Validate credentials
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8',
        ]);

        // Attempt to authenticate the user
        if (Auth::attempt($request->only('email', 'password'))) {
            // Regenerate the session to prevent session fixation
            $request->session()->regenerate();

            // Get the authenticated user
            $user = Auth::user();

            // Create an API token
            $token = $user->createToken('API Token')->plainTextToken;

            // Return the token and user information
            return response()->json([
                'message' => 'Login successful.',
                'token' => $token,
                'user' => $user
            ]);
        }

        // Return error if credentials are invalid
        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    // Logout (revoke token)
    public function logout(Request $request)
    {
        // Revoke the user's current API token
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out successfully.']);
    }
}
