<?php
	error_reporting(E_ALL);
	//Don't run too long. If the Tor client doesn't answers within 10 seconds it's overloaded anyways.
	set_time_limit(10);

	//While the configuration is a JSON object,
	//we store it in a PHP file as a comment to make it safe to have it in a visitor accessible location.
	//If people try to access the file, it will just return blank.
	//Alternatives:
	//- Use a directory outside of the web server file directory
	//- Use a file type that your server refuses to deliver (Apache usually refuses to let users access ".ht*").
	//- Use a subdirectory to limit write permissions to that location
	//Be sure to test that access to the file is not possible for visitors if you use a non-php file extension
	define('CONFIG_FILE','config.php');

	//How many minutes a token will be valid.
	//Don't set too long, especially if you plan to automatically remove requests after a while.
	define('TOKEN_EXPIRATION',10);

	//Possible password characters. You can remove characters that look alike or you can add symbols for added complexity
	//Safe symbols to add: -_.:,;<>{}[]()?!+-*/=&%*#@$');
	//CAUTION! Do not add the double quote (") or non-ASCII symbols.
	define('PASSWORD_CHARSET','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

	//No configuration needed below
	//=============================

	//Similar to many other text based protocols, Tor uses CRLF line ending regardless of the operating system.
	define('CRLF',"\r\n");

	$config=getConfig();
	
	//Checks if the given string is base64
	//It accepts regular b64, url safe b64, and unpadded b64
	function isBase64($x){
		//The shortest possible Base64 sequence is 2 characters without the padding
		//A base64 string can never be n*4+1 in length.
		//In other words, there are never 3 padding characters
		if(!is_string($x) || strlen($x)%4===1){
			return FALSE;
		}
		//Convert URL safe variant into regular Base64
		$x=str_replace('_','/',str_replace('-','+',$x));
		//Add '=' to the end of the string
		while(strlen($x)%4){
			$x.='=';
		}
		return base64_decode($x,TRUE)!==FALSE;
	}
	
	//Checks if the user provided a valid captcha response.
	//If the captcha is disabled, it will also return a success response
	function checkCaptcha(){
		global $config;
		if(useCaptcha()){
			//The captcha response from the user
			$data=av($_POST,'g-recaptcha-response');
			if($data){
				//POST request to google
				$url='https://www.google.com/recaptcha/api/siteverify';
				$data=array(
					'secret'  =>$config['captcha-private'],
					'response'=>$data,
					'remoteip'=>clientIp()
				);
				$options=array(
					'http'=>array(
						'header' =>'Content-type: application/x-www-form-urlencoded' . CRLF,
						'method' =>'POST',
						'content'=>http_build_query($data)
				));
				$context=stream_context_create($options);
				$result=@file_get_contents($url, FALSE, $context);
				
				if($result===FALSE){
					//Google server can't be contacted
					fail('Unable to validate the captcha. Unable to get a response from the captcha server.');
				}
				$response=json_decode($result,TRUE);
				//Check for valid json
				if(json_last_error()!==JSON_ERROR_NONE){
					fail("Unable to decode server answer. Response given: $result");
				}
				//Check success code
				if($response['success']){
					return TRUE;
				}
			}
			return FALSE;
		}
		return TRUE;
	}
	
	//Checks if a captcha is being used
	function useCaptcha(){
		global $config;
		return !empty($config['captcha-private']) && !empty($config['captcha-public']);
	}
	
	//Checks if the configuration is complete (has all keys)
	function configComplete($config){
		if(!is_array($config)){
			return FALSE;
		}
		$required=array('ip','port','password','hmac','showlist','captcha-private','captcha-public');
		foreach($required as $k){
			if(!isset($config[$k])){
				return FALSE;
			}
		}
		return TRUE;
	}

	//Saves the given configuration to the configuration file
	function setConfig($config){
		if(!is_array($config)){
			fail('Attempt to save invalid configuration (not an array)',TRUE);
		}
		//Refuse to update the configuration if key elements are missing
		if(!configComplete($config)){
			fail('Attempt to save configuration that misses a key',TRUE);
		}
		$data=json_encode($config);
		$line="<?php //$data";
		if(!@file_put_contents(CONFIG_FILE,$line)){
			fail('Unable to write to ' . CONFIG_FILE . '. Possible solutions:
- Make sure we have write access to it.
- Change the CONFIG_FILE constant to point to a file that is writable.
- Store this one line in ' . CONFIG_FILE . ' manually: ' . $line,TRUE);
		}
	}

	//Gets the stored configuration
	function getConfig(){
		if(file_exists(CONFIG_FILE)){
			$data=@file(CONFIG_FILE,FILE_IGNORE_NEW_LINES);
			if($data===FALSE || count($data)===0){
				fail('Unable to read configuration file. Make sure we have read access to it.',TRUE);
			}
			//Extract the JSON from the file. We only care about the first line
			if(preg_match('#<\?php\s*//\s*(.+)#',$data[0],$matches)){
				$data=json_decode($matches[1],TRUE);
				$err=json_last_error();
				if($err){
					fail("json_decode() failed with error $err",TRUE);
				}
				return $data;
			}
			fail('Unable to read configuration file: Invalid syntax.
Expected a PHP start tag with a JSON as comment on the first line, but got: ' . $data[0],TRUE);
		}
		return NULL;
	}

	//Prints a line with a linebreak
	function p($x){
		echo $x . CRLF;
	}

	//HTML encode
	function he($x){
		return htmlspecialchars($x);
	}

	//Get array value if it exists and the object is actually an array. Can return a custom default
	function av($a,$v,$d=NULL){
		if(is_array($a) && isset($a[$v]))
		{
			return $a[$v];
		}
		return $d;
	}

	//Validates an IP address
	function isIP($ip){
		return !!filter_var($ip, FILTER_VALIDATE_IP);
	}

	//Gets the client IP address
	function clientIp(){
		return av($_SERVER,'REMOTE_ADDR','0.0.0.0');
	}

	//Computes a HMAC
	function getHmac($value){
		global $config;
		return hash_hmac('sha256',$value,$config['hmac']);
	}

	//Checks if a value matches a HMAC
	function checkHmac($value,$hmac){
		return strtoupper(getHmac($value))===strtoupper($hmac);
	}

	//Generates a random password of the given length
	function mkpasswd($length){
		$pass='';
		while(strlen($pass)<$length){
			//PHP7
			if(function_exists('random_int')){
				$pass.=substr(PASSWORD_CHARSET,random_int(0,strlen(PASSWORD_CHARSET)-1),1);
			}
			//PHP 5.3
			elseif(function_exists('openssl_random_pseudo_bytes')){
				$c=ord(openssl_random_pseudo_bytes(1));
				//Unbiased way to convert a 0-255 value into a smaller range is to simply discard values that are too big.
				//This will potentially throw away a rather large number of values.
				//If this is a problem for you, either update the PHP installation to version 7,
				//or repeat the password charset until it gets close to but not larger than 255 characters.
				if($c<strlen(PASSWORD_CHARSET)){
					$pass.=substr(PASSWORD_CHARSET,$c,1);
				}
			}
			else{
				fail('No suitable safe random number generator present for generating a safe password.
Consider updating PHP',TRUE);
			}
		}
		return $pass;
	}

	//Hashes a password in the same way the TOR client would.
	//TOR hashes passwords weird but simple:
	//1. Generate 8 random bytes as salt value
	//2. Concatenate salt+password
	//3. Repeat the concatenated value until it's 65536 bytes long
	//4. Store as 16:<hex(salt)>60<hex(sha1(value))>
	function hashPassword($password,$salt=NULL){
		//create random salt if it's not supplied (recommended)
		if($salt===NULL){
			if(function_exists('openssl_random_pseudo_bytes')){
				$salt=openssl_random_pseudo_bytes(8);
			}
			else{
				fail('No suitable safe random number generator present for generating a safe salt value.
Consider updating PHP',TRUE);
			}
		}
		//Check supplied salt for validity
		elseif(!is_string($salt) || strlen($salt)!==8){
			fail('Supplied salt value to hashPassword() funtion must be exactly 8 bytes',TRUE);
		}

		//str_pad will properly cut the padding string as needed.
		//"0x60" is the character used to split salt and hash
		//"16:" is probably the internal hash type specifier of Tor
		//"0x10000" is the number of bytes that are hashed.
		return strtoupper('16:' . bin2hex($salt) . dechex(0x60) . sha1(str_pad('',0x10000,"$salt$password")));
	}

	//Tests the password against the configured Tor client
	function testAuth(){
		global $config;
		if($fp=@fsockopen('tcp://' . $config['ip'],$config['port'],$errno,$errstr,5)){
			stream_set_timeout($fp,5);
			fwrite($fp,'AUTHENTICATE "' . $config['password'] . '"' . CRLF . 'QUIT' . CRLF);
			fflush($fp);
			$answer=fgets($fp);
			fclose($fp);
			return stripos($answer,'250 OK')===0;
		}
		return FALSE;
	}

	//Checks if the Tor client is configured as a Relay
	//This is done by checking if the ORPort value has been set
	function isRelay(){
		global $config;
		if($fp=@fsockopen('tcp://' . $config['ip'],$config['port'],$errno,$errstr,5)){
			stream_set_timeout($fp,5);
			fwrite($fp,'AUTHENTICATE "' . $config['password'] . '"' . CRLF);
			fwrite($fp,'GETCONF ORPort' . CRLF);
			fwrite($fp,'QUIT' . CRLF);
			fflush($fp);
			//authentication line
			fgets($fp);
			//ORPort
			$answer=fgets($fp);
			fclose($fp);
			if(preg_match('#^250 orport=\d+$#i',trim($answer))){
				return TRUE;
			}
			return FALSE;
		}
		fail("Connection error $errno: $errstr");
	}

	//Gets the ExitPolicy setting from the config file
	//This contains the explicitly configured values by the user only
	function getRejectConfig($fail=TRUE){
		global $config;
		if($fp=@fsockopen('tcp://' . $config['ip'],$config['port'],$errno,$errstr,5)){
			stream_set_timeout($fp,5);
			$answer='';
			fwrite($fp,'AUTHENTICATE "' . $config['password'] . '"' . CRLF);
			fwrite($fp,'GETCONF ExitPolicy' . CRLF);
			fwrite($fp,'QUIT' . CRLF);
			fflush($fp);
			while(!feof($fp)){
				$data=fgets($fp);
				//FALSE can indicate a stream end, but also an error
				if($data===FALSE){
					if(!feof($fp)){
						fail('Backend did not respond in time. Maybe Tor is overloaded.');
					}
				}else{
					$answer.=$data;
				}
			}
			fclose($fp);
			if(stripos($answer,'exitpolicy')>0){
				if(preg_match_all('#(?:reject|accept)6? [^,\s]+:[^,\s]+#',$answer,$matches)>0){
					return $matches[0];
				}
				//No configured reject/accept lines
				return array();
			}
			if($fail){
				fail('Unable to get ExitPolicy configuration.
Make sure this is an exit relay',TRUE);
			}
			return FALSE;
		}
		fail("Connection error $errno: $errstr");
	}

	//Generates the config line for setRejectConfig()
	function buildConfigLine($reject){
		$ret=array();
		if(count($reject['v4'])>0){
			$ret[]='reject ' . implode(':*,reject ',$reject['v4']) . ':*';
		}
		if(count($reject['v6'])>0){
			$ret[]='reject6 [' . implode(']:*,reject6 ',$reject['v6']) . ']:*';
		}
		if(count($reject['?'])>0){
			$ret[]=implode(',',$reject['?']);
		}
		return implode(',',$ret);
	}

	//Sets the ExitPolicy string in a config file.
	//CAUTION! Will replace existing ExitPolicy setting.
	//Be sure to always supply all values
	function setRejectConfig($reject){
		global $config;
		if($fp=@fsockopen('tcp://' . $config['ip'],$config['port'],$errno,$errstr,5)){
			stream_set_timeout($fp,5);
			$answer='';
			fwrite($fp,'AUTHENTICATE "' . $config['password'] . '"' . CRLF);
			fwrite($fp,"RESETCONF ExitPolicy=\"$reject\"" . CRLF);
			fwrite($fp,'SAVECONF' . CRLF);
			fwrite($fp,'QUIT' . CRLF);
			fflush($fp);
			while(!feof($fp)){
				$data=fgets($fp);
				//FALSE can indicate a stream end, but also an error
				if($data===FALSE){
					if(!feof($fp)){
						fail('Backend did not respond in time. Maybe Tor is overloaded.');
					}
				}else{
					$answer.=$data;
				}
			}
			fclose($fp);
			return $answer;
		}
		fail("Connection error $errno: $errstr");
	}

	//Gets the final policy that Tor computed
	//This includes rejects made by default and the default accept policy.
	//Values are returned in the order they are processed by the client.
	//Tor will stop processing a request on the first match of a rule
	function getComputedPolicy(){
		global $config;
		if($fp=@fsockopen('tcp://' . $config['ip'],$config['port'],$errno,$errstr,5)){
			stream_set_timeout($fp,5);
			$answer='';
			fwrite($fp,'AUTHENTICATE "' . $config['password'] . '"' . CRLF);
			//Defaults in use **before** user supplied policy
			fwrite($fp,'GETINFO exit-policy/reject-private/default' . CRLF);
			//User supplied policy
			fwrite($fp,'GETINFO exit-policy/full' . CRLF);
			//Defaults in use **after** user supplied policy
			fwrite($fp,'GETINFO exit-policy/default' . CRLF);
			fwrite($fp,'QUIT' . CRLF);
			fflush($fp);
			while(!feof($fp)){
				$data=fgets($fp);
				//FALSE can indicate a stream end, but also an error
				if($data===FALSE){
					if(!feof($fp)){
						fail('Backend did not respond in time. Maybe Tor is overloaded.');
					}
				}else{
					$answer.=$data;
				}
			}
			fclose($fp);
			if(preg_match_all('#(?:reject|accept)6? [^,\s]+:[^,\s]+#',$answer,$matches)>0){
				return $matches[0];
			}
			fail('Unable to obtain computed ExitPolicy configuration.
Make sure this is an exit relay',TRUE);
		}
		fail("Connection error $errno: $errstr");
	}

	//Prints a plain text error message with an HTTP 500 header and then exits.
	//Note: Will not actually set the headers if they have been sent already
	function fail($msg,$isConfigError=FALSE){
		if(!headers_sent()){
			header('HTTP/1.1 500 Internal Server Error');
			header('Content-Type: text/plain');
		}
		if($isConfigError===TRUE){
			p('Configuration Error');
			p('===================');
			p($msg);
			p('');
			p('You seem to have misconfigured either the Tor client or this web portal.');
			p('Fix the issue mentioned in the error above, then try again');
		}
		else{
			p('We are unable to process your request at this time.');
			p("Error: $msg");
			p('Errors are usually temporary. If the problem persists over a longer period, contact the owner of this relay');
		}
		exit(0);
	}
