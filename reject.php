<?php
	require_once('include.php');

	//Don't bother doing anything in regards to the black list if the settings are not present
	if(configComplete($config)){
		//Check if the password is still valid
		if(!testAuth()){
			fail('The backend is not accepting the authentication request.
Make sure that the service is runing on the specified port and that the password is valid.
Try restarting tor if the error persists.
Update the password in the configuration if you changed it.',TRUE);
		}

		//Read and parse the black list.
		//The list is split up into IPv4 and IPv6 entries
		$reject=array('v4'=>array(),'v6'=>array(),'?'=>array());
		$configlines=getRejectConfig();
		if(!is_array($configlines)){
			fail($configlines?$configlines:'Unable to obtain black list. Configuration/Password mistake?');
		}
		foreach($configlines as $addr){
			if(preg_match('#reject ([\d\.]+)#',$addr,$matches) && isIP($matches[1])){
				$reject['v4'][]=$matches[1];
			}
			elseif(preg_match('#reject6 \[([^\]]+)\]#',$addr,$matches) && isIP($matches[1])){
				$reject['v6'][]=$matches[1];
			}
			else{
				//It's important to keep unknown reject entries so we don't delete them when we update the list.
				$reject['?'][]=$addr;
			}
		}

		//URL of our own document. If host name or path detection fails, or a port is needed, you can hardcode this.
		//Using HTTP_HOST is a bit questionable because it's the value of a user submitted HTTP header.
		//It's not dangerous if a user tries to submit unreasonable values because it's only for display purposes.
		$url='https://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];

		//Generated token from user form (if it exists that is)
		$token=NULL;
		//Current time for token validation
		$time=time();
		//Get list mode and force it to be one of two values
		$listmode=av($_POST,'listmode');
		if(!in_array($listmode,array('accept','reject'),TRUE)){
			$listmode='reject';
		}
		//API mode. If enabled, will return short messages instead of the HTML document
		//For errors, the status "400 Bad Request" is used if this option is enabled
		$api=FALSE;
		
		//Holds the result of an operation. Text is printed if it's not NULL.
		$result=array('err'=>TRUE,'msg'=>NULL);
		
		switch(av($_POST,'mode')){
			//User wants to generate a token
			case 'token':
				if(checkCaptcha()){
					if(isIP($ip=av($_POST,'ip'))){
						$token=getHmac("$listmode|$time|$ip");
						$result['err']=FALSE;
						$result['msg']='Token generated. Please follow the instructions below';
					}
					else{
						$result['msg']='Invalid IP address. Please enter again';
					}
				}else{
					$result['msg']='invalid captcha response. Please try again';
				}
				break;
			//User wants to block his IP
			case 'reject':
				$api=av($_POST,'api')!=='0';
				//Don't add duplicates
				if(!in_array(clientIp(),$reject['v4'],TRUE) && !in_array(clientIp(),$reject['v4'],TRUE)){
					$time=av($_POST,'time');
					if(is_numeric($time) && $time>time()-(TOKEN_EXPIRATION*60)){
						if(checkHmac("reject|$time|" . clientIp(),av($_POST,'token'))){
							//An IPv6 address has at least one ':' that's not the first character
							if(strpos(':',clientIp())>0){
								$reject['v6'][]=clientIp();
							}
							else{
								$reject['v4'][]=clientIp();
							}
							setRejectConfig(buildConfigLine($reject));
							$result['err']=FALSE;
							$result['msg']='List updated. It can take a short while until requests to your IP die down.';
							//Note: You might want to add something here that will unblock the IP after a while.
							//Bad actors tend to go away after a while
						}else{
							$result['msg']='Invalid token or for different IP address. Make sure the token is for ' . clientIp();
						}
					}else{
						$result['msg']='Token expired';
					}
				}
				else{
					$result['msg']='IP address already in the black list.';
				}
				break;
			//User wants to unblock his IP
			case 'accept':
				$api=av($_POST,'api')!=='0';
				if(in_array(clientIp(),$reject['v4'],TRUE) || in_array(clientIp(),$reject['v4'],TRUE)){
					$time=av($_POST,'time');
					if(is_numeric($time) && $time>time()-(TOKEN_EXPIRATION*60)){
						if(checkHmac("accept|$time|" . clientIp(),av($_POST,'token'))){
							//Remove IP from v4 and v6 entry
							if(($key=array_search(clientIp(), $reject['v4']))!==FALSE){
								unset($reject['v4'][$key]);
							}
							if(($key=array_search(clientIp(), $reject['v6']))!==FALSE){
								unset($reject['v6'][$key]);
							}
							setRejectConfig(buildConfigLine($reject));
							$result['err']=FALSE;
							$result['msg']='List updated. It can take a short while until requests to your IP pick up again.';
						}else{
							$result['msg']='Invalid token or for different IP address. Make sure the token is for ' . clientIp();
						}
					}else{
						$result['msg']='Token expired';
					}
				}
				else{
					$result['msg']='IP address is not in the black list.';
				}
				break;
			default:
				//None/invalid mode
				break;
		}
		if($api){
			if($result['err']){
				header('HTTP/1.1 400 Bad Request');
			}
			header('Content-Type: text/plain');
			echo $result['msg'];
			die(0);
		}
	}else{
		//Logic for initial configuration
		$err=NULL;
		//Check and save configuration
		if(av($_POST,'ip') && av($_POST,'port') && av($_POST,'password')){
			//Empty the configuration before we start
			$config=array();
			//Obtain form values
			$ip=av($_POST,'ip');
			$port=av($_POST,'port');
			$pass=av($_POST,'password');
			
			$captcha=av($_POST,'captcha')==='1';
			$captchaPrivate=av($_POST,'captcha-private');
			$captchaPublic=av($_POST,'captcha-public');
			
			$config['showlist']=av($_POST,'showlist')==='1';
			$config['hmac']=bin2hex(openssl_random_pseudo_bytes(32));
			
			//Validate values that require validation
			if(isIP($ip)){
				$config['ip']=$ip;
			}
			else{
				$err="$ip is an invalid ip address";
			}
			if(is_numeric($port) && $port>0 && $port<0xFFFF){
				$config['port']=+$port;
			}
			else{
				$err="$port is an invalid port number";
			}
			if(strlen($pass)>0 && strpos('"',$pass)===FALSE){
				$config['password']=$pass;
			}
			else{
				$err='Please specify a password. It must not contain double quotes (")';
			}
			//Don't bother checking the captcha values at all if they're not going to be used.
			if($captcha){
				if(isBase64($captchaPrivate)){
					$config['captcha-private']=$captchaPrivate;
				}
				else{
					$err='Invalid reCAPTCHA secret key';
				}
				if(isBase64($captchaPublic)){
					$config['captcha-public']=$captchaPublic;
				}
else{
					$err='Invalid reCAPTCHA public key';
				}
			}else{
				$config['captcha-private']=NULL;
				$config['captcha-public']=NULL;
			}
			
			//Only proceed if no errors were detected so far
			if($err===NULL){
				if(testAuth()){
					if(isRelay()){
						setConfig($config);
						//Redirect so the client makes a new request now that the configuration is set
						header('Location: ' . $_SERVER['PHP_SELF']);
						exit(0);
					}
					else{
						$err='Unable to get the ORPort configuration.
						Make sure your Tor client is configured as a relay.';
						$config=NULL;
					}
				}
				else{
					$err='Unable to validate the password. Invalid password or control connection settings?';
					$config=NULL;
				}
			}
			else{
				$config=NULL;
			}
		}
	}
?><!DOCTYPE html>
<html lang="en">
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<title>Exit Relay Self Service</title>
		<style>
			body{
				font-family:sans-serif;
			}
			code{
				color:#FFF;
				font-weight:bold;
				background-color:#000;
				padding-left:0.25em;
				padding-right:0.25em;
				border:1px solid transparent;
				border-radius:5px;
			}
			a{
				color:#00F;
			}
			[type=submit]{
				padding:0.5em;
			}
			.alert{
				border-size:2px;
				border-style:solid;
				padding:1em;
				max-width:600px;
			}
			.alert-ok{
				border-color:#090;
				color:#090;
			}
			.alert-fail{
				border-color:#F00;
				color:#F00;
			}
			.mono{
				font-family:monospace;
			}
			.twocol{
				max-width:49%;
				display:inline-block;
				vertical-align:top;
			}
		</style>
		<?php if(useCaptcha()){
			echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
		} ?>
	</head>
	<body>
		<h1>Exit Relay Self Service</h1>
		<?php if(configComplete($config)){
			if($result['msg']!==NULL){
				echo '<div class="alert alert-' . ($result['err']?'fail':'ok') . '">' . he($result['msg']) . '</div>';
			} ?>
			<p>
				You can use this portal to add and remove your IP address from our black list.
				Please be aware that blocking access from Tor is usually not going to solve your problems.
				Many exit nodes do not feature an IP black list at all,
				and bad actors will just switch to those or use a different technology like a VPN or proxy server.
				In most cases, implementing features such as rate limiting and captchas is a better solution.
			</p>
			<?php
				if($config['showlist'] && is_array($reject)){
					echo '<h2>Currently blocked addresses</h2>';
					if(count($reject['v4'])===0 && count($reject['v6'])===0){
						echo '<p><i>List is empty</i></p>';
					}
					else{
						echo '<ul>';
						foreach($reject['v4'] as $addr){
							echo '<li>' . he($addr) . '</li>';
						}
						foreach($reject['v6'] as $addr){
							echo '<li>' . he($addr) . '</li>';
						}
						echo '</ul>';
					}
				}
			?>
			<h2>Add/Remove IP</h2>
			<?php if($token){ ?>
				<p>
					Make an HTTP POST request to <code><?php echo he($url); ?></code><br />
					Parameters:
				</p>
				<ul>
					<li><b>token</b>: <code><?php echo he($token); ?></code></li>
					<li><b>time</b>: <code><?php echo he($time); ?></code></li>
					<li><b>mode</b>: <code><?php echo he($listmode); ?></code></li>
				</ul>
				<p>
					The request must originate from the address you submitted and must be made within
					<span id="timer" data-minutes="<?php echo TOKEN_EXPIRATION; ?>" data-time="<?php echo he($time);?>000"><?php echo TOKEN_EXPIRATION; ?> minutes</span>.
					Only then will the IP be processed.<br />
					<a href="<?php echo he($_SERVER['PHP_SELF']);?>">Click here to use a different IP address</a>
				</p>
				<?php if($ip===clientIp()){ ?>
					<form method="post">
						We detected that this is your current IP.
						You can make the request directly in your browser by clicking the button:
						<input type="hidden" name="token" value="<?php echo he($token); ?>" />
						<input type="hidden" name="time" value="<?php echo he($time); ?>" />
						<input type="hidden" name="mode" value="<?php echo he($listmode); ?>" />
						<input type="hidden" name="api" value="0" />
						<input type="submit" value="<?php echo $listmode==='reject'?'Block':'Unblock'; ?> my IP" />
					</form>
				<?php } else { ?>
					<p>
						Tip: If you visit this page from <?php echo he($ip); ?>, you can add/remove it directly in your browser.
					</p>
				<?php } ?>
				<form method="post">
					<input type="hidden" name="ip" value="<?php echo he($ip); ?>" />
					<input type="hidden" name="mode" value="token" />
					<input type="submit" value="Refresh token timer" />
				</form>
			<?php } else{ ?>
				<p>
					Please enter your IP address below to get a black list token.
					IPv4 and IPv6 addresses are accepted
				</p>
				<form method="post">
					<input type="text" name="ip" placeholder="IP address" required value="<?php echo he(clientIp()); ?>" /><br />
					<label><input type="hidden" name="mode" value="token" />
					<label><input type="radio" name="listmode" value="reject" checked /> Add to black list</label><br />
					<label><input type="radio" name="listmode" value="accept" /> Remove from black list</label><br />
					<?php if(useCaptcha()){
						echo '<div class="g-recaptcha" data-sitekey="' . he($config['captcha-public']) . '"></div>';
					} ?>
					<input type="submit" value="Get token" />
				</form>
			<?php } ?>
		<?php } else {
			$ip=av($_POST,'ip','127.0.0.1');
			$port=av($_POST,'port','9051');
			$pass=av($_POST,'password',mkpasswd(20));
			$showlist=av($_POST,'showlist')==='1';
			$captcha=av($_POST,'captcha')==='1';
			$captchaPublic=av($_POST,'captcha-public');
			$captchaPrivate=av($_POST,'captcha-private');
			$torline=hashPassword($pass);
			if($err){
				echo '<div class="alert alert-fail">' . he($err) . '</div>';
			}
		?>
		<p>
			Your instance has not yet been configured.
			Please fill in the values below
		</p>
		<h2>Configuration</h2>
		<p>
			Tor defaults are suggested where applicable.
		</p>
		<form method="post">
			<table>
				<tr>
					<td>Tor Control IP</td>
					<td><input type="text" name="ip" placeholder="IP address" required value="<?php echo he($ip); ?>" /></td>
				</tr>
				<tr>
					<td>Tor Control Port</td>
					<td><input type="number" name="port" min="1" max="65534" required value="<?php echo he($port); ?>" /></td>
				</tr>
				<tr>
					<td>Tor Password</td>
					<td><input type="text" class="mono" name="password" required size="25" value="<?php echo he($pass); ?>" /></td>
				</tr>
				<tr>
					<td>Black list</td>
					<td>
						<label>
							<input type="checkbox" name="showlist" value="1"<?php echo $showlist?' checked':''; ?> />
							Show list of all blocked IP addresses to visitors
						</label>
					</td>
				</tr>
				<tr>
					<td>Captcha</td>
					<td>
						<label>
							<input type="checkbox" name="captcha" value="1"<?php echo $captcha?' checked':''; ?> />
							Use reCAPTCHA to protect the token generator
						</label>
					</td>
				</tr>
				<tr>
					<td>reCAPTCHA public key</td>
					<td><input type="text" class="mono" name="captcha-public" size="50" value="<?php echo he($captchaPublic); ?>"<?php echo $captcha?'':' disabled'; ?>/></td>
				</tr>
				<tr>
					<td>reCAPTCHA secret key</td>
					<td><input type="text" class="mono" name="captcha-private" size="50" value="<?php echo he($captchaPrivate); ?>"<?php echo $captcha?'':' disabled'; ?> /></td>
				</tr>
				<tr>
					<td>&nbsp;</td>
					<td><input type="submit" value="Test and save" /></td>
				</tr>
			</table>
		</form>
		<script>
			(function($){
				var setCaptchaBoxes=function(e){
					$("[name='captcha-public']").disabled=!e;
					$("[name='captcha-private']").disabled=!e;
				};
				$("[name=captcha]").addEventListener("change",function(){
					setCaptchaBoxes($("[name=captcha]").checked);
				});
				setCaptchaBoxes($("[name=captcha]").checked);
			})(document.querySelector.bind(document));
		</script>
		<div class="twocol">
			<h2>reCAPTCHA</h2>
			<p>
				If you want to prevent people from automatically requesting tokens for whatever reason,
				you can enable reCAPTCHA protection.
				You can get free keys by visiting
				<a href="https://www.google.com/recaptcha" target="_blank" rel="noreferer noopener">google.com/recaptcha</a>.
				According to google, reCAPTCHA requires a valid host name but you can enter IP addresses into the field too.
				If in doubt, just enter the reverse DNS entry of your Tor relay public IP.<br />
				<b>Be very careful to put the keys into the correct fields, they look similar</b>
			</p>
		</div>
		<div class="twocol">
			<h2>Enabling the Tor control listener</h2>
			<p>
				To enable the control port, add the line <code>ControlPort 9051</code> to your Tor configuration.
				Change the port number as desired.
				If the line is already present, copy the port number from that line into the field above.
			</p>
			<p>
				To use the password <code><?php echo he($pass); ?></code>,
				add the line <code>HashedControlPassword <?php echo he($torline); ?></code> to the Tor configuration.
				if the line is already present,
				you can either:<br />
				- Use the existing password instead of adding your line<br />
				- Replace the existing line (and the configured password) with the suggested line<br />
				- Add the suggested line to allow your new password while maintaining access for the old one<br />
				<br />
				The last method is recommended because there might be other tools that need control connections
				and they would lose access otherwise.
				You can add a <code>#comment</code> to the configuration file so you know which line is for the portal and which is not.
			</p>
			<p>&rarr; Don't forget to restart your Tor client after making the changes</p>
		</div>
		
		<?php } ?>
		<p>
			<a href="https://github.com/AyrA/ERSS" target="_blank" rel="noreferer noopener">Exit Relay Self Service</a> is free and open software,
			<a href="https://github.com/AyrA/ERSS/LICENSE">licensed under the MIT</a>
		</p>
	</body>
</html>
