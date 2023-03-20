<?php

namespace App\Http\Controllers\API;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function login(Request $request)
    {
        try{
        //  validate request
            $request->validate([
                'email' =>'required|email',
                'password' => 'required',
            ]);


        // find user by email
        $cradentials = request(['email','password']);
        if(!Auth::attempt($cradentials)){
            return ResponseFormatter::error('Unauthorized',401);
        }
        $user = User::where('email',$request->email)->first();
        if(!Hash::check($request->password, $user->password)) {
            throw new Exception('Invalid password');

        }
        // $user = User::where('email', $request->email)->firstOrFail();
        // if (!Hash::check($request->password, $user->password)) {
        //     throw new Exception('Invalid password');
        // }
        // generate token
        $toketResult = $user->createToken('authToken')->plainTextToken;
        
        // return response
        return ResponseFormatter::success([
            'access_token' => $toketResult,
            'token_type' => 'Bearer',
            'user' => $user
        ],'login Successful'); 
        }
        catch (Exception $e)
        {
            return ResponseFormatter::error('Autentication Failed');
        }

      
    }
    public function register(Request $request)
    {
        try{
            //validate request
            $request->validate([
                'name' =>['required','string','max:255'],
                'email' =>['required','string','email','max:255','unique:users'],
                'password' =>['required','string',new Password],
                
            ]);
           
            //create user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            //generate token
            $tokenResult = $user->createToken('authToken')->plainTextToken;
           
            //return response
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'bearer',
                'user' => $user
            ],'login Successful');

        }catch (Exception $eror){

            //return eror response
            return ResponseFormatter::error($eror->getMessage(),$eror->getCode());
        }
    }
    public function logout(Request $request)
    {
        //Revoke token
        $token = $request->user()->currentAccessToken()->delete();

        //return response
        return ResponseFormatter::success($token,'Logout success');
    }
    public function fetch(Request $request)
    {
        //get user
        $user = $request->user();

        // return response
        return ResponseFormatter::success($user,'Data user berhasil diambil');
    }
}
