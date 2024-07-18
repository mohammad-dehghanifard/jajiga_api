<?php

namespace App\Controllers;

use App\Database\QueryBuilder;
use App\Traits\ResponseTrait;
use App\Auth\JWTAuth as JWTAuth;
use App\Validations\ValidateData;

class AuthController
{
    use ResponseTrait;
    use JWTAuth;
    use ValidateData;

    protected $queryBuilder;

    public function __construct()
    {
        $this->queryBuilder = new QueryBuilder();
    }


    public function test()
    {
        $query = $this->queryBuilder->table("users")->getAll()->execute();
        return $this->sendResponse(data: $query);
    }

    public function login($request)
    {
        // validate request
        $this->validate([
            'username||min:3|max:25',
            'mobile_number||required|min:8',
        ], $request);
        $findUser = null;
        // get user
        if(isset($request->mobile_number))
        {
            $findUser = $this->queryBuilder->table('users')
                ->where('mobile', '=', $request->mobile_number)
                ->get()->execute();
        }elseif (isset($request->username)){
            $findUser = $this->queryBuilder->table('users')
                ->where('username', '=', $request->username)
                ->get()->execute();
        }


        if ($findUser) {
            // Generate JWT token
            $token = $this->generateToken($findUser->username, $request->mobile_number);

            // Return token as JSON response
            return $this->sendResponse(data: ['token' => $token,], message: "با موفقیت وارد شدید");
        } else {
            // If credentials are not valid, return error response
            return $this->sendResponse(message: "نام کاربری یا رمز عبور شما صحیح نیست!", error: true, status:  HTTP_Unauthorized);
        }
    }

    public function register($request){
        // validate request
        $this->validate([
            'username||required|min:3|max:25|string',
            'display_name||main:3|max:40|string',
            'mobile_number||required|min:8',
            "role||enum:admin,guest,host,supporter",
            "status||enum:pending,reject,accept",
        ], $request);
        $this->checkUnique('users', 'username', $request->username);
        $this->checkUnique('users', 'mobile', $request->mobile_number);

        $newUser = $this->queryBuilder->table('users')
            ->insert([
                'username' => $request->username,
                'mobile' => $request->mobile_number,
                "display_name" => $request->display_name ?? Null,
                "profile_image" => $request->profile_image ?? Null,
                "role" => $request->role ?? "guest",
                "status" => $request->status ?? "pending",


            ])->execute();

        return $this->sendResponse(data: $newUser, message: "حساب کاربری شما با موفقیت ایجاد شد!");
    }

    public function verify($request){
        $verification = $this->verifyToken($request->token);

        return $this->sendResponse(data:$verification, message: "Unauthorized token body!" ,error: true, status: HTTP_BadREQUEST);
    }
}