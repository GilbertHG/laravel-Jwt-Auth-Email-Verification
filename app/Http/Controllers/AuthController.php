<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Validator;
use DB, Hash, Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Mail\Message;

class AuthController extends Controller
{
    //

    public function register(Request $request){
    	$rules=[
    		'name'=>'required|max:255',
    		'email'=>'required|max:255|unique:users',
    		'password'=>'required|confirmed|min:6'
    	];

    	$input=$request->only(
    		'name',
    		'email',
    		'password',
    		'password_confirmation'
    		);

    	$validator= Validator::make($input,$rules);

    	if($validator->fails()){
    		$error = $validator->messages()->toJson();
    		return response()->json(['success'=>false,'error'=>$error]);
    	}

    	$name = $request->name;
    	$email = $request->email;
    	$password = $request->password;

    	$user=User::create([
    		'name'=>$name,
    		'email'=>$email,
    		'password'=>Hash::make($password)
    		]);

    	$verification_code = str_random(30);
    	DB::table('user_verifications')->insert([
    		'user_id'=>$user->id,
    		'token'=>$verification_code
    		]);

    	$subject = 'Please verify your email address';

    	Mail::send('email.verify', ['name'=>$name,'verification_code'=>$verification_code],
    		function($mail) use ($email,$name,$subject){
    			$mail->from('sutralian@gmail.com','test verify');
    			$mail->to($email,$name);
    			$mail->subject($subject);
    		});

    	return response()->json(['success'=> true, 'message'=> 'Thanks for signing up! Please check your email to complete your registration.']);
    }


    public function verifyUser($verification_code){
    	$check=DB::table('user_verifications')->where('token',$verification_code)->first();
    	if(!is_null($check)){
    		$user=User::find($check->user_id);

    		if($user->is_verified == 1){
    			return response()->json([
    				'success'=>true,
    				'message'=>'Account already verified'
    				]);
    		}

    		$user->update(['is_verified'=>1]);
    		DB::table('user_verifications')->where('token',$verification_code)->delete();

    		return response()->json([
    			'success'=>true,
    			'message'=>'you have successfully verified your email address'
    			]);


    	}

    	return response()->json([
    		'status'=>false,
    		'error'=>'verification code is invalid!!'
    		]);
    }


    public function login(Request $request){
    	$rules=[
    		'email'=>'required|email',
    		'password'=>'required'
    		];

    	$input=$request->only('email','password');

    	$validator = Validator::make($input,$rules);

    	if($validator->fails()){
    		$error=$validator->messages()->toJson();
    		return response()->json([
    			'success'=>false,
    			'error'=>$error
    			]);
    	}

    	$credentials=[
    		'email'=>$request->email,
    		'password'=>$request->password,
    		'is_verified'=>1
    	];

    	try{
    		if(!$token = JWTAuth::attempt($credentials)){
    			return response()->json([
    				'success'=>false,
    				'error'=>'invalid credentials, please make sure you entered the right information and you have verified'
    				]);
    		}
    	}
    	catch(JWTException $e){
    		return response()->json([
    			'success'=>false,
    			'error'=>'could not create auth token'
    			]);
    	}

    	return response()->json([
    		'success'=>true,
    		'token'=>$token
    		]);
    }


    public function logout(Request $request){
    	$this->validate($request,['token'=>'required']);

    	try{
    		JWTAuth::invalidate($request->input('token'));
    		return response()->json(['success'=>true]);
    	}
    	catch(JWTException $e){	

    		return response()->json(['success'=>false,'error'=>'failed to logou please try again']);

    	}
    }

    public function recover(Request $request){
    	$user= User::where('email',$request->email)->first();

    	if(!$user){
    		$error_message = 'your email address was not found';
    		return response()->json([
    			'success'=>false,
    			'error'=>$error_message
    			]);
    	}

    	try{
    		Password::sendResetLink($request->only('email'),function(Message $message){
    			$message=subject('your password reset link');
    		});
    	}
    	catch(JWTException $e){
    		$error=$e->getMessage();
    		return response()->json([
    			'success'=>false,
    			'error'=>$error
    			]);
    	}

    	return response()->json([
            'success' => true, 'data'=> ['msg'=> 'A reset email has been sent! Please check your email.']
        ]);
    }
}
