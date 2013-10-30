<?php

	function _get_provider_config($provider) {
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

			case 'Yandex':
				$this->oauth_version = '2.0';
				$this->request_token_url = 'https://oauth.yandex.com/authorize';
				$this->dialog_url = 'https://oauth.yandex.com/authorize';
				$this->access_token_url = 'https://oauth.yandex.com/verification_code';
				$this->authorization_header = false;
				break;

			case 'vk':
				$this->oauth_version = '2.0';
#	$this->baseApiUri = new Uri('https://api.vk.com/method/');
#	return new Uri('https://oauth.vk.com/authorize');
#	return new Uri('https://oauth.vk.com/access_token');

#				$this->request_token_url = 'https://oauth.yandex.com/authorize';
#				$this->dialog_url = 'https://oauth.yandex.com/authorize';
#				$this->access_token_url = 'https://oauth.yandex.com/verification_code';
				$this->authorization_header = false;
				break;

			case 'amazon':
				$this->oauth_version = '2.0';
#	$this->baseApiUri = new Uri('https://api.amazon.com/');
#	return new Uri('https://www.amazon.com/ap/oa');
#	return new Uri('https://www.amazon.com/ap/oatoken');

#				$this->request_token_url = 'https://oauth.yandex.com/authorize';
#				$this->dialog_url = 'https://oauth.yandex.com/authorize';
#				$this->access_token_url = 'https://oauth.yandex.com/verification_code';
				$this->authorization_header = false;
				break;

			default:
				return($this->SetError($this->server.' is not yet a supported type of OAuth server. Please contact the author Manuel Lemos <mlemos@acm.org> to request adding built-in support to this type of OAuth server.'));
		}
		return(true);
	}
