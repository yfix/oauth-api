<?php
	require('../.dev/config.php');

	require('../http/http.php');
	require('../oauth/oauth_client.php');

	$client = new oauth_client_class;
	$client->debug = 1;
	$client->debug_http = 1;
	$client->server = 'Yandex';
	$client->redirect_uri = 'http://'.$_SERVER['HTTP_HOST'].dirname(strtok($_SERVER['REQUEST_URI'],'?')).'/'.basename(__FILE__);

	$client->client_id = $config['yandex']['client_id'] ?: ''; $application_line = __LINE__;
	$client->client_secret = $config['yandex']['client_secret'] ?: '';

	if(strlen($client->client_id) == 0
	|| strlen($client->client_secret) == 0)
		die('Please provide client_id and client_secret');

	if(($success = $client->Initialize()))
	{
		if(($success = $client->Process()))
		{
			if(strlen($client->access_token))
			{
				$success = $client->CallAPI(
					'https://api.yandex.com/api/me',
					'GET', array(), array('FailOnAccessError'=>true), $user);
			}
		}
		$success = $client->Finalize($success);
	}
	if($client->exit)
		exit;
	if($success)
	{
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>OAuth client results</title>
</head>
<body>
<?php
		echo '<h1>', HtmlSpecialChars($user->display_name), 
			' you have logged in successfully with Github!</h1>';
		echo '<pre>', HtmlSpecialChars(print_r($user, 1)), '</pre>';
?>
</body>
</html>
<?php
	}
	else
	{
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>OAuth client error</title>
</head>
<body>
<h1>OAuth client error</h1>
<p>Error: <?php echo HtmlSpecialChars($client->error); ?></p>
</body>
</html>
<?php
	}

?>