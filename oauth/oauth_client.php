<?php

class oauth_client_class
{
	var $error = '';
	var $debug = false;
	var $debug_http = false;
	var $exit = false;
	var $debug_output = '';
	var $debug_prefix = 'OAuth client: ';
	var $server = '';
	var $request_token_url = '';
	var $dialog_url = '';
	var $offline_dialog_url = '';
	var $append_state_to_redirect_uri = '';
	var $access_token_url = '';
	var $oauth_version = '2.0';
	var $url_parameters = false;
	var $authorization_header = true;
	var $token_request_method = 'GET';
	var $signature_method = 'HMAC-SHA1';
	var $redirect_uri = '';
	var $client_id = '';
	var $client_secret = '';
	var $api_key = '';
	var $get_token_with_api_key = false;
	var $scope = '';
	var $offline = false;
	var $access_token = '';
	var $access_token_secret = '';
	var $access_token_expiry = '';
	var $access_token_type = '';
	var $default_access_token_type = '';
	var $access_token_parameter = '';
	var $access_token_response;
	var $store_access_token_response = false;
	var $refresh_token = '';
	var $access_token_error = '';
	var $authorization_error = '';
	var $response_status = 0;
	var $oauth_user_agent = 'PHP-OAuth-API';
	var $session_started = false;

	function SetError($error)
	{
		$this->error = $error;
		if($this->debug)
			$this->OutputDebug('Error: '.$error);
		return(false);
	}

	function SetPHPError($error, &$php_error_message)
	{
		if(IsSet($php_error_message)
		&& strlen($php_error_message))
			$error.=": ".$php_error_message;
		return($this->SetError($error));
	}

	function OutputDebug($message)
	{
		if($this->debug)
		{
			$message = $this->debug_prefix.$message;
			$this->debug_output .= $message."\n";;
			error_log($message);
		}
		return(true);
	}

	function GetRequestTokenURL(&$request_token_url)
	{
		$request_token_url = $this->request_token_url;
		return(true);
	}

	function GetDialogURL(&$url, $redirect_uri = '', $state = '')
	{
		$url = (($this->offline && strlen($this->offline_dialog_url)) ? $this->offline_dialog_url : $this->dialog_url);
		if(strlen($url) === 0)
			return $this->SetError('the dialog URL '.($this->offline ? 'for offline access ' : '').'is not defined for this server');
		$url = str_replace(
			'{REDIRECT_URI}', UrlEncode($redirect_uri), str_replace(
			'{STATE}', UrlEncode($state), str_replace(
			'{CLIENT_ID}', UrlEncode($this->client_id), str_replace(
			'{API_KEY}', UrlEncode($this->api_key), str_replace(
			'{SCOPE}', UrlEncode($this->scope),
			$url)))));
		return(true);
	}

	function GetAccessTokenURL(&$access_token_url)
	{
		$access_token_url = str_replace('{API_KEY}', $this->api_key, $this->access_token_url);
		return(true);
	}

	function GetStoredState(&$state)
	{
		if(!$this->session_started)
		{
			if(!function_exists('session_start'))
				return $this->SetError('Session variables are not accessible in this PHP environment');
		}
		if(IsSet($_SESSION['OAUTH_STATE']))
			$state = $_SESSION['OAUTH_STATE'];
		else
			$state = $_SESSION['OAUTH_STATE'] = time().'-'.substr(md5(rand().time()), 0, 6);
		return(true);
	}

	function GetRequestState(&$state)
	{
		$check = (strlen($this->append_state_to_redirect_uri) ? $this->append_state_to_redirect_uri : 'state');
		$state = (IsSet($_GET[$check]) ? $_GET[$check] : null);
		return(true);
	}

	function GetRequestCode(&$code)
	{
		$code = (IsSet($_GET['code']) ? $_GET['code'] : null);
		return(true);
	}

	function GetRequestError(&$error)
	{
		$error = (IsSet($_GET['error']) ? $_GET['error'] : null);
		return(true);
	}

	function GetRequestDenied(&$denied)
	{
		$denied = (IsSet($_GET['denied']) ? $_GET['denied'] : null);
		return(true);
	}

	function GetRequestToken(&$token, &$verifier)
	{
		$token = (IsSet($_GET['oauth_token']) ? $_GET['oauth_token'] : null);
		$verifier = (IsSet($_GET['oauth_verifier']) ? $_GET['oauth_verifier'] : null);
		return(true);
	}

	function GetRedirectURI(&$redirect_uri)
	{
		if(strlen($this->redirect_uri))
			$redirect_uri = $this->redirect_uri;
		else
			$redirect_uri = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
		return true;
	}

	function Redirect($url)
	{
		Header('HTTP/1.0 302 OAuth Redirection');
		Header('Location: '.$url);
	}

	function StoreAccessToken($access_token)
	{
		if(!$this->session_started)
		{
			if(!function_exists('session_start'))
				return $this->SetError('Session variables are not accessible in this PHP environment');
		}
		if(!$this->GetAccessTokenURL($access_token_url))
			return false;
		$_SESSION['OAUTH_ACCESS_TOKEN'][$access_token_url] = $access_token;
		return true;
	}

	function GetAccessToken(&$access_token)
	{
		if(!$this->session_started)
		{
			if(!function_exists('session_start'))
				return $this->SetError('Session variables are not accessible in this PHP environment');
			if(!session_start())
				return($this->SetPHPError('it was not possible to start the PHP session', $php_error_message));
			$this->session_started = true;
		}
		if(!$this->GetAccessTokenURL($access_token_url))
			return false;
		if(IsSet($_SESSION['OAUTH_ACCESS_TOKEN'][$access_token_url]))
			$access_token = $_SESSION['OAUTH_ACCESS_TOKEN'][$access_token_url];
		else
			$access_token = array();
		return true;
	}

	function ResetAccessToken()
	{
		if(!$this->GetAccessTokenURL($access_token_url))
			return false;
		if($this->debug)
			$this->OutputDebug('Resetting the access token status for OAuth server located at '.$access_token_url);
		if(!$this->session_started)
		{
			if(!function_exists('session_start'))
				return $this->SetError('Session variables are not accessible in this PHP environment');
			if(!session_start())
				return($this->SetPHPError('it was not possible to start the PHP session', $php_error_message));
		}
		$this->session_started = true;
		if(IsSet($_SESSION['OAUTH_ACCESS_TOKEN'][$access_token_url]))
			Unset($_SESSION['OAUTH_ACCESS_TOKEN'][$access_token_url]);
		return true;
	}

	function Encode($value)
	{
		return(is_array($value) ? $this->EncodeArray($value) : str_replace('%7E', '~', str_replace('+',' ', RawURLEncode($value))));
	}

	function EncodeArray($array)
	{
		foreach($array as $key => $value)
			$array[$key] = $this->Encode($value);
		return $array;
	}

	function HMAC($function, $data, $key)
	{
		switch($function)
		{
			case 'sha1':
				$pack = 'H40';
				break;
			default:
				if($this->debug)
					$this->OutputDebug($function.' is not a supported an HMAC hash type');
				return('');
		}
		if(strlen($key) > 64)
			$key = pack($pack, $function($key));
		if(strlen($key) < 64)
			$key = str_pad($key, 64, "\0");
		return(pack($pack, $function((str_repeat("\x5c", 64) ^ $key).pack($pack, $function((str_repeat("\x36", 64) ^ $key).$data)))));
	}

	function SendAPIRequest($url, $method, $parameters, $oauth, $options, &$response)
	{
		$this->response_status = 0;
		$http = new http_class;
		$http->debug = ($this->debug && $this->debug_http);
		$http->log_debug = true;
		$http->sasl_authenticate = 0;
		$http->user_agent = $this->oauth_user_agent;
		$http->redirection_limit = (IsSet($options['FollowRedirection']) ? intval($options['FollowRedirection']) : 0);
		$http->follow_redirect = ($http->redirection_limit != 0);
		if($this->debug)
			$this->OutputDebug('Accessing the '.$options['Resource'].' at '.$url);
		$post_files = array();
		$method = strtoupper($method);
		$authorization = '';
		$type = (IsSet($options['RequestContentType']) ? strtolower(trim(strtok($options['RequestContentType'], ';'))) : 'application/x-www-form-urlencoded');
		if(IsSet($oauth))
		{
			$values = array(
				'oauth_consumer_key'=>$this->client_id,
				'oauth_nonce'=>md5(uniqid(rand(), true)),
				'oauth_signature_method'=>$this->signature_method,
				'oauth_timestamp'=>time(),
				'oauth_version'=>'1.0',
			);
			$files = (IsSet($options['Files']) ? $options['Files'] : array());
			if(count($files))
			{
				foreach($files as $name => $value)
				{
					if(!IsSet($parameters[$name]))
						return($this->SetError('it was specified an file parameters named '.$name));
					$file = array();
					switch(IsSet($value['Type']) ? $value['Type'] : 'FileName')
					{
						case 'FileName':
							$file['FileName'] = $parameters[$name];
							break;
						case 'Data':
							$file['Data'] = $parameters[$name];
							break;
						default:
							return($this->SetError($value['Type'].' is not a valid type for file '.$name));
					}
					$file['ContentType'] = (IsSet($value['Content-Type']) ? $value['Content-Type'] : 'automatic/name');
					$post_files[$name] = $file;
				}
				UnSet($parameters[$name]);
				if($method !== 'POST')
				{
					$this->OutputDebug('For uploading files the method should be POST not '.$method);
					$method = 'POST';
				}
				if($type !== 'multipart/form-data')
				{
					if(IsSet($options['RequestContentType']))
						return($this->SetError('the request content type for uploading files should be multipart/form-data'));
					$type = 'multipart/form-data';
				}
				$value_parameters = array();
			}
			else
			{
				if($this->url_parameters
				&& $type === 'application/x-www-form-urlencoded'
				&& count($parameters))
				{
					$first = (strpos($url, '?') === false);
					foreach($parameters as $parameter => $value)
					{
						$url .= ($first ? '?' : '&').UrlEncode($parameter).'='.UrlEncode($value);
						$first = false;
					}
					$parameters = array();
				}
				$value_parameters = ($type !== 'application/x-www-form-urlencoded' ? array() : $parameters);
			}
			$values = array_merge($values, $oauth, $value_parameters);
			$key = $this->Encode($this->client_secret).'&'.$this->Encode($this->access_token_secret);
			switch($this->signature_method)
			{
				case 'PLAINTEXT':
					$values['oauth_signature'] = $key;
					break;
				case 'HMAC-SHA1':
					$uri = strtok($url, '?');
					$sign = $method.'&'.$this->Encode($uri).'&';
					$first = true;
					$sign_values = $values;
					$u = parse_url($url);
					if(IsSet($u['query']))
					{
						parse_str($u['query'], $q);
						foreach($q as $parameter => $value)
							$sign_values[$parameter] = $value;
					}
					KSort($sign_values);
					foreach($sign_values as $parameter => $value)
					{
						$sign .= $this->Encode(($first ? '' : '&').$parameter.'='.$this->Encode($value));
						$first = false;
					}
					$values['oauth_signature'] = base64_encode($this->HMAC('sha1', $sign, $key));
					break;
				default:
					return $this->SetError($this->signature_method.' signature method is not yet supported');
			}
			if($this->authorization_header)
			{
				$authorization = 'OAuth';
				$first = true;
				foreach($values as $parameter => $value)
				{
					$authorization .= ($first ? ' ' : ',').$parameter.'="'.$this->Encode($value).'"';
					$first = false;
				}
			}
			else
			{
				if($method === 'GET'
				|| (IsSet($options['PostValuesInURI'])
				&& $options['PostValuesInURI']))
				{
					$first = (strcspn($url, '?') == strlen($url));
					foreach($values as $parameter => $value)
					{
						$url .= ($first ? '?' : '&').$parameter.'='.$this->Encode($value);
						$first = false;
					}
					$post_values = array();
				}
				else
					$post_values = $values;
			}
		}
		if(strlen($authorization) === 0
		&& !strcasecmp($this->access_token_type, 'Bearer'))
			$authorization = 'Bearer '.$this->access_token;
		if(strlen($error = $http->GetRequestArguments($url, $arguments)))
			return($this->SetError('it was not possible to open the '.$options['Resource'].' URL: '.$error));
		if(strlen($error = $http->Open($arguments)))
			return($this->SetError('it was not possible to open the '.$options['Resource'].' URL: '.$error));
		if(count($post_files))
			$arguments['PostFiles'] = $post_files;
		$arguments['RequestMethod'] = $method;
		switch($type)
		{
			case 'application/x-www-form-urlencoded':
			case 'multipart/form-data':
				if(IsSet($options['RequestBody']))
					return($this->SetError('the request body is defined automatically from the parameters'));
				$arguments['PostValues'] = $parameters;
				break;
			case 'application/json':
				$arguments['Headers']['Content-Type'] = $options['RequestContentType'];
				if(!IsSet($options['RequestBody']))
				{
					$arguments['Body'] = json_encode($parameters);
					break;
				}
			default:
				if(!IsSet($options['RequestBody']))
					return($this->SetError('it was not specified the body value of the of the API call request'));
				$arguments['Headers']['Content-Type'] = $options['RequestContentType'];
				$arguments['Body'] = $options['RequestBody'];
				break;
		}
		$arguments['Headers']['Accept'] = (IsSet($options['Accept']) ? $options['Accept'] : '*/*');
		if(strlen($authorization))
			$arguments['Headers']['Authorization'] = $authorization;
		if(strlen($error = $http->SendRequest($arguments))
		|| strlen($error = $http->ReadReplyHeaders($headers)))
		{
			$http->Close();
			return($this->SetError('it was not possible to retrieve the '.$options['Resource'].': '.$error));
		}
		$error = $http->ReadWholeReplyBody($data);
		$http->Close();
		if(strlen($error))
		{
			return($this->SetError('it was not possible to access the '.$options['Resource'].': '.$error));
		}
		$this->response_status = intval($http->response_status);
		$content_type = (IsSet($options['ResponseContentType']) ? $options['ResponseContentType'] : (IsSet($headers['content-type']) ? strtolower(trim(strtok($headers['content-type'], ';'))) : 'unspecified'));
		switch($content_type)
		{
			case 'text/javascript':
			case 'application/json':
				if(!function_exists('json_decode'))
					return($this->SetError('the JSON extension is not available in this PHP setup'));
				$object = json_decode($data);
				switch(GetType($object))
				{
					case 'object':
						if(!IsSet($options['ConvertObjects'])
						|| !$options['ConvertObjects'])
							$response = $object;
						else
						{
							$response = array();
							foreach($object as $property => $value)
								$response[$property] = $value;
						}
						break;
					case 'array':
						$response = $object;
						break;
					default:
						if(!IsSet($object))
							return($this->SetError('it was not returned a valid JSON definition of the '.$options['Resource'].' values'));
						$response = $object;
						break;
				}
				break;
			case 'application/x-www-form-urlencoded':
			case 'text/plain':
			case 'text/html':
				parse_str($data, $response);
				break;
			default:
				$response = $data;
				break;
		}
		if($this->response_status >= 200
		&& $this->response_status < 300)
			$this->access_token_error = '';
		else
		{
			$this->access_token_error = 'it was not possible to access the '.$options['Resource'].': it was returned an unexpected response status '.$http->response_status.' Response: '.$data;
			if($this->debug)
				$this->OutputDebug('Could not retrieve the OAuth access token. Error: '.$this->access_token_error);
			if(IsSet($options['FailOnAccessError'])
			&& $options['FailOnAccessError'])
			{
				$this->error = $this->access_token_error;
				return false;
			}
		}
		return true;
	}

	function ProcessToken($code, $refresh)
	{
		if($refresh)
		{
			$values = array(
				'client_id'=>$this->client_id,
				'client_secret'=>($this->get_token_with_api_key ? $this->api_key : $this->client_secret),
				'refresh_token'=>$this->refresh_token,
				'grant_type'=>'refresh_token'
			);
		}
		else
		{
			if(!$this->GetRedirectURI($redirect_uri))
				return false;
			$values = array(
				'code'=>$code,
				'client_id'=>$this->client_id,
				'client_secret'=>($this->get_token_with_api_key ? $this->api_key : $this->client_secret),
				'redirect_uri'=>$redirect_uri,
				'grant_type'=>'authorization_code'
			);
		}
		if(!$this->GetAccessTokenURL($access_token_url))
			return false;
		if(!$this->SendAPIRequest($access_token_url, 'POST', $values, null, array('Resource'=>'OAuth '.($refresh ? 'refresh' : 'access').' token', 'ConvertObjects'=>true), $response))
			return false;
		if(strlen($this->access_token_error))
		{
			$this->authorization_error = $this->access_token_error;
			return true;
		}
		if(!IsSet($response['access_token']))
		{
			if(IsSet($response['error']))
			{
				$this->authorization_error = 'it was not possible to retrieve the access token: it was returned the error: '.$response['error'];
				return true;
			}
			return($this->SetError('OAuth server did not return the access token'));
		}
		$access_token = array(
			'value'=>($this->access_token = $response['access_token']),
			'authorized'=>true,
		);
		if($this->store_access_token_response)
			$access_token['response'] = $this->access_token_response = $response;
		if($this->debug)
			$this->OutputDebug('Access token: '.$this->access_token);
		if(IsSet($response['expires_in'])
		&& $response['expires_in'] == 0)
		{
			if($this->debug)
				$this->OutputDebug('Ignoring access token expiry set to 0');
			$this->access_token_expiry = '';
		}
		elseif(IsSet($response['expires'])
		|| IsSet($response['expires_in']))
		{
			$expires = (IsSet($response['expires']) ? $response['expires'] : $response['expires_in']);
			if(strval($expires) !== strval(intval($expires))
			|| $expires <= 0)
				return($this->SetError('OAuth server did not return a supported type of access token expiry time'));
			$this->access_token_expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
			if($this->debug)
				$this->OutputDebug('Access token expiry: '.$this->access_token_expiry.' UTC');
			$access_token['expiry'] = $this->access_token_expiry;
		}
		else
			$this->access_token_expiry = '';
		if(IsSet($response['token_type']))
		{
			$this->access_token_type = $response['token_type'];
			if(strlen($this->access_token_type)
			&& $this->debug)
				$this->OutputDebug('Access token type: '.$this->access_token_type);
			$access_token['type'] = $this->access_token_type;
		}
		else
		{
			$this->access_token_type = $this->default_access_token_type;
			if(strlen($this->access_token_type)
			&& $this->debug)
				$this->OutputDebug('Assumed the default for OAuth access token type which is '.$this->access_token_type);
		}
		if(IsSet($response['refresh_token']))
		{
			$this->refresh_token = $response['refresh_token'];
			if($this->debug)
				$this->OutputDebug('New refresh token: '.$this->refresh_token);
			$access_token['refresh'] = $this->refresh_token;
		}
		elseif(strlen($this->refresh_token))
		{
			if($this->debug)
				$this->OutputDebug('Reusing previous refresh token: '.$this->refresh_token);
			$access_token['refresh'] = $this->refresh_token;
		}
		if(!$this->StoreAccessToken($access_token))
			return false;
		return true;
	}

	function RetrieveToken(&$valid)
	{
		$valid = false;
		if(!$this->GetAccessToken($access_token))
			return false;
		if(IsSet($access_token['value']))
		{
			$this->access_token_expiry = '';
			if(IsSet($access_token['expiry'])
			&& strcmp($this->access_token_expiry = $access_token['expiry'], gmstrftime('%Y-%m-%d %H:%M:%S')) < 0)
			{
				if($this->debug)
					$this->OutputDebug('The OAuth access token expired in '.$this->access_token_expiry);
			}
			$this->access_token = $access_token['value'];
			if($this->debug)
				$this->OutputDebug('The OAuth access token '.$this->access_token.' is valid');
			if(IsSet($access_token['type']))
			{
				$this->access_token_type = $access_token['type'];
				if(strlen($this->access_token_type)
				&& $this->debug)
					$this->OutputDebug('The OAuth access token is of type '.$this->access_token_type);
			}
			else
			{
				$this->access_token_type = $this->default_access_token_type;
				if(strlen($this->access_token_type)
				&& $this->debug)
					$this->OutputDebug('Assumed the default for OAuth access token type which is '.$this->access_token_type);
			}
			if(IsSet($access_token['secret']))
			{
				$this->access_token_secret = $access_token['secret'];
				if($this->debug)
					$this->OutputDebug('The OAuth access token secret is '.$this->access_token_secret);
			}
			if(IsSet($access_token['refresh']))
				$this->refresh_token = $access_token['refresh'];
			else
				$this->refresh_token = '';
			$this->access_token_response = (($this->store_access_token_response && IsSet($access_token['response'])) ? $access_token['response'] : null);
			$valid = true;
		}
		return true;
	}

	function CallAPI($url, $method, $parameters, $options, &$response)
	{
		if(!IsSet($options['Resource']))
			$options['Resource'] = 'API call';
		if(!IsSet($options['ConvertObjects']))
			$options['ConvertObjects'] = false;
		if(strlen($this->access_token) === 0)
		{
			if(!$this->RetrieveToken($valid))
				return false;
			if(!$valid)
				return $this->SetError('the access token is not set to a valid value');
		}
		switch(intval($this->oauth_version))
		{
			case 1:
				$oauth = array(
					(strlen($this->access_token_parameter) ? $this->access_token_parameter : 'oauth_token')=>((IsSet($options['2Legged']) && $options['2Legged']) ? '' : $this->access_token)
				);
				break;

			case 2:
				if(strlen($this->access_token_expiry)
				&& strcmp($this->access_token_expiry, gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0)
				{
					if(strlen($this->refresh_token) === 0)
						return($this->SetError('the access token expired and no refresh token is available'));
					if($this->debug)
					{
						$this->OutputDebug('The access token expired on '.$this->access_token_expiry);
						$this->OutputDebug('Refreshing the access token');
					}
					if(!$this->ProcessToken(null, true))
						return false;
				}
				$oauth = null;
				if(strcasecmp($this->access_token_type, 'Bearer'))
					$url .= (strcspn($url, '?') < strlen($url) ? '&' : '?').(strlen($this->access_token_parameter) ? $this->access_token_parameter : 'access_token').'='.UrlEncode($this->access_token);
				break;

			default:
				return($this->SetError($this->oauth_version.' is not a supported version of the OAuth protocol'));
		}
		return($this->SendAPIRequest($url, $method, $parameters, $oauth, $options, $response));
	}

	function Initialize()
	{
		if(strlen($this->server) === 0)
			return true;
		$this->request_token_url = '';
		$this->append_state_to_redirect_uri = '';
		$this->authorization_header = true;
		$this->url_parameters = false;
		$this->token_request_method = 'GET';
		$this->signature_method = 'HMAC-SHA1';
		switch($this->server)
		{
			case 'Bitbucket':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://bitbucket.org/!api/1.0/oauth/request_token';
				$this->dialog_url = 'https://bitbucket.org/!api/1.0/oauth/authenticate';
				$this->access_token_url = 'https://bitbucket.org/!api/1.0/oauth/access_token';
				$this->url_parameters = false;
				break;

			case 'Box':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://www.box.com/api/oauth2/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={STATE}';
				$this->offline_dialog_url = 'https://www.box.com/api/oauth2/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={STATE}&access_type=offline&approval_prompt=force';
				$this->access_token_url = 'https://www.box.com/api/oauth2/token';
				break;

			case 'Disqus':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://disqus.com/api/oauth/2.0/authorize/?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->access_token_url = 'https://disqus.com/api/oauth/2.0/access_token/';
				break;

			case 'Dropbox':
				$this->oauth_version = '1.0';
				$this->request_token_url = 'https://api.dropbox.com/1/oauth/request_token';
				$this->dialog_url = 'https://www.dropbox.com/1/oauth/authorize';
				$this->access_token_url = 'https://api.dropbox.com/1/oauth/access_token';
				$this->authorization_header = false;
				break;

			case 'Eventful':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'http://eventful.com/oauth/request_token';
				$this->dialog_url = 'http://eventful.com/oauth/authorize';
				$this->access_token_url = 'http://eventful.com/oauth/access_token';
				$this->authorization_header = false;
				$this->url_parameters = true;
				$this->token_request_method = 'POST';
				break;

			case 'Evernote':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://sandbox.evernote.com/oauth';
				$this->dialog_url = 'https://sandbox.evernote.com/OAuth.action';
				$this->access_token_url = 'https://sandbox.evernote.com/oauth';
				$this->url_parameters = true;
				$this->authorization_header = false;
				break;

			case 'Facebook':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://www.facebook.com/dialog/oauth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->access_token_url = 'https://graph.facebook.com/oauth/access_token';
				break;

			case 'Fitbit':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'http://api.fitbit.com/oauth/request_token';
				$this->dialog_url = 'http://api.fitbit.com/oauth/authorize';
				$this->access_token_url = 'http://api.fitbit.com/oauth/access_token';
				break;

			case 'Flickr':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'http://www.flickr.com/services/oauth/request_token';
				$this->dialog_url = 'http://www.flickr.com/services/oauth/authorize?perms={SCOPE}';
				$this->access_token_url = 'http://www.flickr.com/services/oauth/access_token';
				$this->authorization_header = false;
				break;

			case 'Foursquare':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://foursquare.com/oauth2/authorize?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}&state={STATE}';
				$this->access_token_url = 'https://foursquare.com/oauth2/access_token';
				$this->access_token_parameter = 'oauth_token';
				break;

			case 'github':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->access_token_url = 'https://github.com/login/oauth/access_token';
				break;

			case 'Google':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->offline_dialog_url = 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}&access_type=offline&approval_prompt=force';
				$this->access_token_url = 'https://accounts.google.com/o/oauth2/token';
				break;

			case 'Instagram':
				$this->oauth_version = '2.0';
				$this->dialog_url ='https://api.instagram.com/oauth/authorize/?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&response_type=code&state={STATE}';
				$this->access_token_url = 'https://api.instagram.com/oauth/access_token';
				break;

			case 'LinkedIn':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken?scope={SCOPE}';
				$this->dialog_url = 'https://api.linkedin.com/uas/oauth/authenticate';
				$this->access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken';
				$this->url_parameters = true;
				break;

			case 'Microsoft':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://login.live.com/oauth20_authorize.srf?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}&state={STATE}';
				$this->access_token_url = 'https://login.live.com/oauth20_token.srf';
				break;

			case 'RightSignature':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://rightsignature.com/oauth/request_token';
				$this->dialog_url = 'https://rightsignature.com/oauth/authorize';
				$this->access_token_url = 'https://rightsignature.com/oauth/access_token';
				$this->authorization_header = false;
				break;

			case 'Salesforce':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://login.salesforce.com/services/oauth2/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->access_token_url = 'https://login.salesforce.com/services/oauth2/token';
				$this->default_access_token_type = 'Bearer';
				$this->store_access_token_response = true;
				break;

			case 'Scoop.it':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://www.scoop.it/oauth/request';
				$this->dialog_url = 'https://www.scoop.it/oauth/authorize';
				$this->access_token_url = 'https://www.scoop.it/oauth/access';
				$this->authorization_header = false;
				break;

			case 'StockTwits':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://api.stocktwits.com/api/2/oauth/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
				$this->access_token_url = 'https://api.stocktwits.com/api/2/oauth/token';
				break;

			case 'SurveyMonkey':
				$this->oauth_version = '2.0';
				$this->dialog_url = 'https://api.surveymonkey.net/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={STATE}&api_key={API_KEY}';
				$this->access_token_url = 'https://api.surveymonkey.net/oauth/token?api_key={API_KEY}';
				break;

			case 'Tumblr':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'http://www.tumblr.com/oauth/request_token';
				$this->dialog_url = 'http://www.tumblr.com/oauth/authorize';
				$this->access_token_url = 'http://www.tumblr.com/oauth/access_token';
				break;

			case 'Twitter':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://api.twitter.com/oauth/request_token';
				$this->dialog_url = 'https://api.twitter.com/oauth/authenticate';
				$this->access_token_url = 'https://api.twitter.com/oauth/access_token';
				$this->url_parameters = true;
				break;

			case 'XING':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://api.xing.com/v1/request_token';
				$this->dialog_url = 'https://api.xing.com/v1/authorize';
				$this->access_token_url = 'https://api.xing.com/v1/access_token';
				$this->authorization_header = false;
				break;

			case 'Yahoo':
				$this->oauth_version = '1.0a';
				$this->request_token_url = 'https://api.login.yahoo.com/oauth/v2/get_request_token';
				$this->dialog_url = 'https://api.login.yahoo.com/oauth/v2/request_auth';
				$this->access_token_url = 'https://api.login.yahoo.com/oauth/v2/get_token';
				$this->authorization_header = false;
				break;

			default:
				return($this->SetError($this->server.' is not yet a supported type of OAuth server. Please contact the author Manuel Lemos <mlemos@acm.org> to request adding built-in support to this type of OAuth server.'));
		}
		return(true);
	}

	function Process()
	{
		switch(intval($this->oauth_version))
		{
			case 1:
				$one_a = ($this->oauth_version === '1.0a');
				if($this->debug)
					$this->OutputDebug('Checking the OAuth token authorization state');
				if(!$this->GetAccessToken($access_token))
					return false;
				if(IsSet($access_token['authorized'])
				&& IsSet($access_token['value']))
				{
					$expired = (IsSet($access_token['expiry']) && strcmp($access_token['expiry'], gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0);
					if(!$access_token['authorized']
					|| $expired)
					{
						if($this->debug)
						{
							if($expired)
								$this->OutputDebug('The OAuth token expired on '.$access_token['expiry'].'UTC');
							else
								$this->OutputDebug('The OAuth token is not yet authorized');
							$this->OutputDebug('Checking the OAuth token and verifier');
						}
						if(!$this->GetRequestToken($token, $verifier))
							return false;
						if(!IsSet($token)
						|| ($one_a
						&& !IsSet($verifier)))
						{
							if(!$this->GetRequestDenied($denied))
								return false;
							if(IsSet($denied)
							&& $denied === $access_token['value'])
							{
								if($this->debug)
									$this->OutputDebug('The authorization request was denied');
								$this->authorization_error = 'the request was denied';
								return true;
							}
							else
							{
								if($this->debug)
									$this->OutputDebug('Reset the OAuth token state because token and verifier are not both set');
								$access_token = array();
							}
						}
						elseif($token !== $access_token['value'])
						{
							if($this->debug)
								$this->OutputDebug('Reset the OAuth token state because token does not match what as previously retrieved');
							$access_token = array();
						}
						else
						{
							if(!$this->GetAccessTokenURL($url))
								return false;
							$oauth = array(
								'oauth_token'=>$token,
							);
							if($one_a)
								$oauth['oauth_verifier'] = $verifier;
							$this->access_token_secret = $access_token['secret'];
							$options = array('Resource'=>'OAuth access token');
							$method = strtoupper($this->token_request_method);
							switch($method)
							{
								case 'GET':
									break;
								case 'POST':
									$options['PostValuesInURI'] = true;
									break;
								default:
									$this->error = $method.' is not a supported method to request tokens';
									break;
							}
							if(!$this->SendAPIRequest($url, $method, array(), $oauth, $options, $response))
								return false;
							if(strlen($this->access_token_error))
							{
								$this->authorization_error = $this->access_token_error;
								return true;
							}
							if(!IsSet($response['oauth_token'])
							|| !IsSet($response['oauth_token_secret']))
							{
								$this->authorization_error= 'it was not returned the access token and secret';
								return true;
							}
							$access_token = array(
								'value'=>$response['oauth_token'],
								'secret'=>$response['oauth_token_secret'],
								'authorized'=>true
							);
							if(IsSet($response['oauth_expires_in'])
							&& $response['oauth_expires_in'] == 0)
							{
								if($this->debug)
									$this->OutputDebug('Ignoring access token expiry set to 0');
								$this->access_token_expiry = '';
							}
							elseif(IsSet($response['oauth_expires_in']))
							{
								$expires = $response['oauth_expires_in'];
								if(strval($expires) !== strval(intval($expires))
								|| $expires <= 0)
									return($this->SetError('OAuth server did not return a supported type of access token expiry time'));
								$this->access_token_expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
								if($this->debug)
									$this->OutputDebug('Access token expiry: '.$this->access_token_expiry.' UTC');
								$access_token['expiry'] = $this->access_token_expiry;
							}
							else
								$this->access_token_expiry = '';

							if(!$this->StoreAccessToken($access_token))
								return false;
							if($this->debug)
								$this->OutputDebug('The OAuth token was authorized');
						}
					}
					elseif($this->debug)
						$this->OutputDebug('The OAuth token was already authorized');
					if(IsSet($access_token['authorized'])
					&& $access_token['authorized'])
					{
						$this->access_token = $access_token['value'];
						$this->access_token_secret = $access_token['secret'];
						return true;
					}
				}
				else
				{
					if($this->debug)
						$this->OutputDebug('The OAuth access token is not set');
					$access_token = array();
				}
				if(!IsSet($access_token['authorized']))
				{
					if($this->debug)
						$this->OutputDebug('Requesting the unauthorized OAuth token');
					if(!$this->GetRequestTokenURL($url))
						return false;
					$url = str_replace('{SCOPE}', UrlEncode($this->scope), $url); 
					if(!$this->GetRedirectURI($redirect_uri))
						return false;
					$oauth = array(
						'oauth_callback'=>$redirect_uri,
					);
					$options = array(
						'Resource'=>'OAuth request token',
						'FailOnAccessError'=>true
					);
					$method = strtoupper($this->token_request_method);
					switch($method)
					{
						case 'GET':
							break;
						case 'POST':
							$options['PostValuesInURI'] = true;
							break;
						default:
							$this->error = $method.' is not a supported method to request tokens';
							break;
					}
					if(!$this->SendAPIRequest($url, $method, array(), $oauth, $options, $response))
						return false;
					if(strlen($this->access_token_error))
					{
						$this->authorization_error = $this->access_token_error;
						return true;
					}
					if(!IsSet($response['oauth_token'])
					|| !IsSet($response['oauth_token_secret']))
					{
						$this->authorization_error = 'it was not returned the requested token';
						return true;
					}
					$access_token = array(
						'value'=>$response['oauth_token'],
						'secret'=>$response['oauth_token_secret'],
						'authorized'=>false
					);
					if(!$this->StoreAccessToken($access_token))
						return false;
				}
				if(!$this->GetDialogURL($url))
					return false;
				$url .= (strpos($url, '?') === false ? '?' : '&').'oauth_token='.$access_token['value'];
				if(!$one_a)
				{
					if(!$this->GetRedirectURI($redirect_uri))
						return false;
					$url .= '&oauth_callback='.UrlEncode($redirect_uri);
				}
				if($this->debug)
					$this->OutputDebug('Redirecting to OAuth authorize page '.$url);
				$this->Redirect($url);
				$this->exit = true;
				return true;

			case 2:
				if($this->debug)
				{
					if(!$this->GetAccessTokenURL($access_token_url))
						return false;
					$this->OutputDebug('Checking if OAuth access token was already retrieved from '.$access_token_url);
				}
				if(!$this->RetrieveToken($valid))
					return false;
				if($valid)
					return true;
				if($this->debug)
					$this->OutputDebug('Checking the authentication state in URI '.$_SERVER['REQUEST_URI']);
				if(!$this->GetStoredState($stored_state))
					return false;
				if(strlen($stored_state) == 0)
					return($this->SetError('it was not set the OAuth state'));
				if(!$this->GetRequestState($state))
					return false;
				if($state === $stored_state)
				{
					if($this->debug)
						$this->OutputDebug('Checking the authentication code');
					if(!$this->GetRequestCode($code))
						return false;
					if(strlen($code) == 0)
					{
						if(!$this->GetRequestError($this->authorization_error))
							return false;
						if(IsSet($this->authorization_error))
						{
							if($this->debug)
								$this->OutputDebug('Authorization failed with error code '.$this->authorization_error);
							switch($this->authorization_error)
							{
								case 'invalid_request':
								case 'unauthorized_client':
								case 'access_denied':
								case 'unsupported_response_type':
								case 'invalid_scope':
								case 'server_error':
								case 'temporarily_unavailable':
								case 'user_denied':
									return true;
								default:
									return($this->SetError('it was returned an unknown OAuth error code'));
							}
						}
						return($this->SetError('it was not returned the OAuth dialog code'));
					}
					if(!$this->ProcessToken($code, false))
						return false;
				}
				else
				{
					if(!$this->GetRedirectURI($redirect_uri))
						return false;
					if(strlen($this->append_state_to_redirect_uri))
						$redirect_uri .= (strpos($redirect_uri, '?') === false ? '?' : '&').$this->append_state_to_redirect_uri.'='.$stored_state;
					if(!$this->GetDialogURL($url, $redirect_uri, $stored_state))
						return false;
					if(strlen($url) == 0)
						return($this->SetError('it was not set the OAuth dialog URL'));
					if($this->debug)
						$this->OutputDebug('Redirecting to OAuth Dialog '.$url);
					$this->Redirect($url);
					$this->exit = true;
				}
				break;

			default:
				return($this->SetError($this->oauth_version.' is not a supported version of the OAuth protocol'));
		}
		return(true);
	}

	function Finalize($success)
	{
		return($success);
	}

	function Output()
	{
		if(strlen($this->authorization_error)
		|| strlen($this->access_token_error)
		|| strlen($this->access_token))
		{
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>OAuth client result</title>
</head>
<body>
<h1>OAuth client result</h1>
<?php
			if(strlen($this->authorization_error))
			{
?>
<p>It was not possible to authorize the application.<?php
				if($this->debug)
				{
?>
<br>Authorization error: <?php echo HtmlSpecialChars($this->authorization_error);
				}
?></p>
<?php
			}
			elseif(strlen($this->access_token_error))
			{
?>
<p>It was not possible to use the application access token.
<?php
				if($this->debug)
				{
?>
<br>Error: <?php echo HtmlSpecialChars($this->access_token_error);
				}
?></p>
<?php
			}
			elseif(strlen($this->access_token))
			{
?>
<p>The application authorization was obtained successfully.
<?php
				if($this->debug)
				{
?>
<br>Access token: <?php echo HtmlSpecialChars($this->access_token);
					if(IsSet($this->access_token_secret))
					{
?>
<br>Access token secret: <?php echo HtmlSpecialChars($this->access_token_secret);
					}
				}
?></p>
<?php
				if(strlen($this->access_token_expiry))
				{
?>
<p>Access token expiry: <?php echo $this->access_token_expiry; ?> UTC</p>
<?php
				}
			}
?>
</body>
</html>
<?php
		}
	}

};

?>