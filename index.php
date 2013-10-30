<?php

/*
	+-----------------+------------------------------------------------------------+
	|  Script         | PHProxy   +  SabzProxy + html2js                           |
	|  Modifier       | Forgetful + Timo Van Neerden + Amaury Carrade + webdev23   |
	|  Last Modified  | 11:55 PM 10/30/2013                                        |
	+-----------------+------------------------------------------------------------+
	|  This program is free software; you can redistribute it and/or               |
	|  modify it under the terms of the GNU General Public License                 |
	|  as published by the Free Software Foundation; either version 2              |
	|  of the License, or (at your option) any later version.                      |
	|                                                                              |
	|  This program is distributed in the hope that it will be useful,             |
	|  but WITHOUT ANY WARRANTY; without even the implied warranty of              |
	|  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               |
	|  GNU General Public License for more details.                                |
	+------------------------------------------------------------------------------+

Last author: http://webdev23.com
*/


// CONFIGURABLE OPTIONS
//

// Default values
$_flags = array (
	'remove_scripts'  => false,
	'accept_cookies'  => true,
	'show_referer'    => true,
	'session_cookies' => true
);


// TODO : put these in GLOBALS LANG
$_labels = array(
	'remove_scripts' => array('Remove client-side scripting (I.E, Javascript)', 'Remove client-side scripting'), 
	'accept_cookies' => array('Allow cookies to be stored', 'Allow cookies to be stored'), 
	'show_referer' => array('Send my referer to the websites', 'Send my referer to the websites'), 
	'base64_encode' => array('Use Base64 encoding of URLs', 'Base64'), 
	'session_cookies' => array('Store cookies for this session only ', 'Store cookies for this session only ') 
);


// Put here the hosts blacklisted by the server.
// /!\ Parsed as a regular expression. Don't forget to escape characters.
$_hosts_blacklisted = array(
	// empêche de lire le localhost (plus pratique pour éviter qu'un visiteur lise de localhost de votre serveur, donc votre serveur
	'#^127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost#i',
);

//
// END CONFIGURABLE OPTIONS.
//

function vd($var) { var_dump($var); }

session_name('prx');
session_start(); 

// Random key for URL (prevent from blocking)
if(!isset($_SESSION['urlKey']) || empty($_SESSION['urlKey'])) {
	$_SESSION['urlKey'] = substr(urlencode(sha1(uniqid(mt_rand(), true))), 0, 6);
}
$q  = $_SESSION['urlKey'];
$hl = substr(urlencode(sha1($q)), 0, 8);


// Calculate HMAC-SHA1 according to RFC2104
// http://www.ietf.org/rfc/rfc2104.txt
function hmacsha1($key,$data) {
	$blocksize = 64;
	$hashfunc = 'sha1';
	if (strlen($key) > $blocksize) $key = pack('H*', $hashfunc($key));
	$key = str_pad($key, $blocksize, chr(0x00));
	$ipad = str_repeat(chr(0x36), $blocksize);
	$opad = str_repeat(chr(0x5c), $blocksize);
	$hmac = pack('H*', $hashfunc(($key^$opad).pack('H*', $hashfunc(($key^$ipad).$data))));
	return bin2hex($hmac);
}

// Simple XOR encryption taken from:
// http://www.jonasjohn.de/snippets/php/xor-encryption.htm
function XOREncryption($InputString, $KeyPhrase) {
	$KeyPhraseLength = strlen($KeyPhrase);

	// Loop trough input string
	for ($i = 0; $i < strlen($InputString); $i++) {
		$rPos = $i % $KeyPhraseLength; // Get key phrase character position
		$r = ord($InputString[$i]) xor ord($KeyPhrase[$rPos]); // Magic happens here:
		$InputString[$i] = chr($r); // Replace characters
	}
	return $InputString;
}

// Helper functions, using base64 to
// create readable encrypted texts: 
function XOREncrypt64($InputString, $KeyPhrase){
	$InputString = XOREncryption($InputString, $KeyPhrase);
	$InputString = base64_encode($InputString);
	return $InputString;
}

function XORDecrypt64($InputString, $KeyPhrase){
	$InputString = base64_decode($InputString);
	$InputString = XOREncryption($InputString, $KeyPhrase);
	return $InputString;
}


if (!isset($_SESSION['randomkey'])) {
  $_SESSION['randomkey'] = sha1(uniqid('',true).'_'.mt_rand());
}




$_iflags = '';
$_system = array(
	'ssl' => extension_loaded('openssl') and version_compare(PHP_VERSION, '4.3.0', '>='),
	'uploads' => ini_get('file_uploads'),
	'gzip' => extension_loaded('zlib') and !ini_get('zlib.output_compression'),
	'stripslashes' => get_magic_quotes_gpc()
);

$_proxify = array(
	'text/html' => 1,
	'application/xml+xhtml' => 1,
	'application/xhtml+xml' => 1,
	'text/css' => 1
);

$_http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
$_http_s = ( (isset($_ENV['HTTPS']) and $_ENV['HTTPS'] == 'on') or $_SERVER['SERVER_PORT'] == 443) ? 'https' : 'http';
$_http_port = ($_SERVER['SERVER_PORT'] != 80 and $_SERVER['SERVER_PORT'] != 443 ? ':'.$_SERVER['SERVER_PORT'] : '');
$_script_url = $_http_s.'://'.$_http_host.$_http_port.$_SERVER['PHP_SELF'];

$_script_base  = substr($_script_url, 0, strrpos($_script_url, '/')+1);

/////////////////


$_socket = null;
$_request_method = $_SERVER['REQUEST_METHOD'];
$_post_body = '';
$_set_cookie = array();

//
// FUNCTION DECLARATIONS
//


function add_cookie($name, $value, $expires = 0) {
	return rawurlencode(rawurlencode($name)).'='.rawurlencode(rawurlencode($value)).(empty($expires) ? '' : '; expires=' . gmdate('D, d-M-Y H:i:s \G\M\T', $expires)) . '; path=/; domain=.' . $GLOBALS['_http_host'];
}

function set_post_vars($array, $parent_key = null) {
	$temp = array();
	foreach ($array as $key => $value) {
		$key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
		if (is_array($value)) {
			$temp = array_merge($temp, set_post_vars($value, $key));
		}
		else {
			$temp[$key] = urlencode($value);
		}
	}
	return $temp;
}

function set_post_files($array, $parent_key = null) {
	$temp = array();
	foreach ($array as $key => $value) {
		$key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
		if (is_array($value)) {
			$temp = array_merge_recursive($temp, set_post_files($value, $key));
		}
		elseif (preg_match('#^([^\[\]]+)\[(name|type|tmp_name)\]#', $key, $m)) {
			$temp[str_replace($m[0], $m[1], $key)][$m[2]] = $value;
		}
	}
	return $temp;
}

function url_parse($url, & $container) {
	$temp = @parse_url($url);

	if (!empty($temp)) {
		$temp['port_ext'] = '';
		$temp['base'] = $temp['scheme'].'://'.$temp['host'];

		// ajoute le port si donné
		if (isset($temp['port'])) {
			$temp['base'] .= $temp['port_ext'] = ':' . $temp['port'];
		}
		// port SSL (443) si https, 80 sinon.
		else {
			$temp['port'] = $temp['scheme'] === 'https' ? 443 : 80;
		}
		// si le path existe, on le garde, sinon c'est un chemin relatif
		$temp['path'] = isset($temp['path']) ? $temp['path'] : '/';
		$path = array();
		$temp['path'] = explode('/', $temp['path']);

		foreach ($temp['path'] as $dir) {
			if ($dir === '..') {
				array_pop($path); // permet de réduire le nombre de dossiers si on a un retour en haut=> /foo/../bar =>> /bar
			}
			elseif ($dir !== '.') {
/*				$dir = rawurldecode($dir);
				$count_i = strlen($dir);
				// reconstruit le nom du dossier char par char (évite le genre de truc comme %20 dans les dossiers dâÃªtres parsÃ©s comme des sÃ©parateursâŠ)
					// je pense qu'il y a beaucoup plus simple, mais bon.
				for ($new_dir = '', $i = 0 ; $i < $count_i; $i++) {
					$new_dir .= strspn($dir[$i], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*\'(),?:@&;=') ? $dir[$i] : rawurlencode($dir[$i]);
				}
				$path[] = $new_dir;
*/

				$path[] = rawurlencode($dir);
			}
		}

		$temp['path'] = '/'.ltrim(implode('/', $path), '/'); // supprime tous les '/' à gauche et en ajoute un seul : ///fol/file => /fol/file
		$temp['file'] = substr($temp['path'], strrpos($temp['path'], '/')+1);
		$temp['dir'] = substr($temp['path'], 0, strrpos($temp['path'], '/'));
		$temp['base'] .= $temp['dir'];
		$temp['prev_dir'] = substr_count($temp['path'], '/') > 1 ? substr($temp['base'], 0, strrpos($temp['base'], '/')+1) : $temp['base'] . '/';
		$container = $temp;

		return true;
	}

	return false;
}

function complete_url($url, $proxify = true) {
	$url = trim($url);
	if ($url === '') {
		return '';
	}

	$hash_pos = strrpos($url, '#');
	$fragment = $hash_pos !== false ? '#' . substr($url, $hash_pos) : '';
	$sep_pos  = strpos($url, '://');

	if ($sep_pos === false || $sep_pos > 5) {
		switch ($url{0}) {
			case '/':
				$url = substr($url, 0, 2) === '//' ? $GLOBALS['_base']['scheme'] . ':' . $url : $GLOBALS['_base']['scheme'] . '://' . $GLOBALS['_base']['host'] . $GLOBALS['_base']['port_ext'] . $url;
				break;
			case '?':
				$url = $GLOBALS['_base']['base'] . '/' . $GLOBALS['_base']['file'] . $url;
				break;
			case '#':
				$proxify = false;
				break;
			case 'm':
				if (substr($url, 0, 7) == 'mailto:') {
					$proxify = false;
          				break;
        			}
      			case 'j':
        			if (substr($url, 0, 11) == 'javascript:') {
          				$proxify = false;
          				break;
       				}
			default:
				$url = $GLOBALS['_base']['base'] . '/' . $url;
				break;
		}
	}

	//$url = str_replace('&amp;', '&', $url);
	return $proxify ? "{$GLOBALS['_script_url']}?" . $GLOBALS['q'] . "=" . encode_url($url) . $fragment : $url;
}

function proxify_inline_css($css) {
	preg_match_all('#url\s{0,}\(("|\')?([^\'")]{1,})(\'|")?\)#i', $css, $matches, PREG_SET_ORDER);
	for ($i = 0, $count = count($matches); $i < $count; ++$i) {
      if (!preg_match('#^data:#', $matches[$i][2])) {
			$css = str_replace($matches[$i][0], 'url("' . proxify_css_url($matches[$i][2]) . '")', $css);
		}
	}
	return $css;
}

function proxify_css($css) {
	$css = proxify_inline_css($css);

	preg_match_all("#@import\s*(?:\"([^\">]*)\"?|'([^'>]*)'?)([^;]*)(;|$)#i", $css, $matches, PREG_SET_ORDER);

	for ($i = 0, $count = count($matches); $i < $count; ++$i) {
		$delim = '"';
		$url = $matches[$i][2];

		if (!empty($matches[$i][3])) {
			$delim = "'";
			$url = $matches[$i][3];
		}

		$css = str_replace($matches[$i][0], '@import ' . $delim . proxify_css_url($url) . $delim . (!empty($matches[$i][4]) ? $matches[$i][4] : ''), $css);
	}

	return $css;
}

function proxify_css_url($url) {
	$url = trim($url);
	$delim = strpos($url, '"') === 0 ? '"' : (strpos($url, "'") === 0 ? "'" : '');
	return $delim . preg_replace('#([\(\),\s\'"\\\])#', '\\$1', complete_url(trim(preg_replace('#\\\(.)#', '$1', trim($url, $delim))))) . $delim;
}

//
// SET FLAGS
//

if (isset($_POST[$q]) and !isset($_GET[$q]) and isset($_POST[$hl])) {
	foreach ($_flags as $flag_name => $flag_value) {
		$_iflags .= isset($_POST[$hl][$flag_name]) ? (string)(int)(bool)$_POST[$hl][$flag_name] : 0;
	}
	$_iflags = base_convert(($_iflags != '' ? $_iflags : '0'), 2, 16);
}

elseif (isset($_GET[$hl]) and !isset($_GET['____pgfa']) and ctype_alnum($_GET[$hl])) {
	$_iflags = $_GET[$hl];
}

elseif (isset($_COOKIE['flags']) and ctype_alnum($_COOKIE['flags'])) {
	$_iflags = $_COOKIE['flags'];
}

if ($_iflags !== '') {
	$_set_cookie[] = add_cookie('flags', $_iflags, time()+2419200);
	$_iflags = str_pad(base_convert($_iflags, 16, 2), count($_flags), '0', STR_PAD_LEFT);
	$i = 0;

	foreach ($_flags as $flag_name => $flag_value) {
		$_flags[$flag_name] = (int)(bool)$_iflags{$i};
		$i++;
	}
}


function encode_url($url) {
	$encrypted_url = XOREncrypt64($url,$_SESSION['randomkey']);
	$hmac = hmacsha1( $_SESSION['randomkey'], $encrypted_url);
	return rawurlencode($hmac.$encrypted_url);
}

function decode_url($url) {
	$s = rawurldecode($url);
	$hmac = substr($s,0,40);
	$encrypted_url = substr($s,40,strlen($s)-40);

	// Make sure hmac is correct
	if ($hmac != hmacsha1($_SESSION['randomkey'], $encrypted_url)) { 
		echo "Wrong hmac.";
		exit; // Violent, but effective.
	}

	// Decrypt the URL
	$cleartext_url = XORDecrypt64($encrypted_url, $_SESSION['randomkey']);
	return str_replace(array('&amp;', '&#38;'), '&', $cleartext_url);
}


//
// STRIP SLASHES FROM GPC IF NECESSARY
//

function clean_txt($text) {
	if (!get_magic_quotes_gpc()) {
		$return = trim(addslashes($text));
	} else {
		$return = trim($text);
	}
return $return;
}


function clean_txt_array($array) {
	foreach ($array as $i => $key) {
		if (is_array($array[$i])) {
			clean_txt_array($key);
		}
		else {
			$array[$i] = clean_txt($key);
		}
	}
	return $array;
}

$_GET = clean_txt_array($_GET);
$_POST = clean_txt_array($_POST);
$_COOKIE = clean_txt_array($_COOKIE);




//
// FIGURE OUT WHAT TO DO (POST URL-form submit, GET form request, regular request, basic auth, cookie manager, show URL-form)
//

if (isset($_POST[$q]) && !isset($_GET[$q]) && !isset($_POST['____pgfa'])) {
	header('Location: '.$_script_url.'?'.$q.'='.encode_url($_POST[$q]).'&'.$hl.'='.base_convert($_iflags, 2, 16));
	exit(0);
}

if (isset($_POST['____pgfa'])) {
	$_url = ($_POST['____pgfa']);
	$qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url)-1 ? '' : '&') : '?';
	$arr = explode('&', $_SERVER['QUERY_STRING']);

	$getquery = "";
	foreach($_POST as $key => $val){
		if ($key != '____pgfa') {
			$getquery .= "&".$key."=".$val;
		}
	}

	$getquerylen = strlen($getquery);
	$getquery = substr($getquery, 1, $getquerylen-1);

	if (preg_match('#^\Q' . '____pgfa' . '\E#', $arr[0])) {
		array_shift($arr);
	}

	$_url .= $qstr.$getquery;
	$_gotourl = complete_url($_url);
	$_request_method = 'GET';
}

elseif (isset($_GET[$q])) {
    $_url  = decode_url($_GET[$q]);
    $qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url)-1 ? '' : '&') : '?';
    $arrs = explode('&', $_SERVER['QUERY_STRING']);

    foreach($arrs AS $key => $arr) {
	    if (preg_match('#^\Q(' . $q . '|' . $hl . ')\E#', $arr))
	    {
	        unset($arrs[$key]);
	    }
	}
    $_url .= $qstr . implode('&', $arrs);

    // Removing $q and $hl from the URL
    // Some websites doesn't work wothout the exact URL entered (i.e. with some GET params like
    // our $q & $hl).
    $_url = preg_replace('#(' . $q . '|' . $hl . ')=(.*)(&)?#i', NULL, $_url);
}

else {
	afficher_page_form(array('type' => 'empty-form', 'flag' => ''));
}


function afficher_page_form($page) {
	$url = isset($GLOBALS['_url']) ? htmlspecialchars($GLOBALS['_url']) : '';

	echo '<!DOCTYPE html>'."\n";
	echo '<html>'."\n";
	echo '<head>'."\n";
	echo '	<meta charset="utf-8" />'."\n";
	echo '  <link rel="shortcut icon" href="data:image/vnd.microsoft.icon;base64,AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAAAA7XcAAAAAAAD/DQAAPyAAAPF5AAD2ewAAMRkAAP1/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAERERERERERESIiIiIiIiISIiIiIiIiIiIiIiIRIiIiIiIiIRESIiIiIiIhERciIiIhEiIRIiIiIiESIiIiIiIhIiIiIiIiIhEREREREREREXd3F3dxd3cRQwcXN3FzdxFzdxc3cXNXEXEXFxZxcRcREREREREREREREREREREREAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//wAA" />' . "\n";
	echo '	<title>WebShooter - Remotely screenshot every website</title>'."\n";
        echo '  <script src="js/jquery.1.9.1.js"></script>'."\n";
	echo '<style type="text/css">'."\n";

	echo 'body { background:#FFF; width: 100%; margin:0; padding:0; }
#orpx_nav-bar { height: 24px; padding: 4px 0; margin: 0; text-align: center; border-bottom: 1px solid #755; color: #000; background-color: #232323; font-size: 13px; }
#orpx_nav-bar a { color: #000; }
#orpx_nav-bar a:hover { color: #007744; }
.windows-popup { background-color: #BF6464; border-top: 1px solid #44352C; border-bottom: 1px solid #44352C; clear: both; padding: 30px 0; text-align: center; margin-top: 152px; }
.windows-popup { background-color: #666666;color:white;font-size:20px; }
.windows-popup p, .windows-popup form { margin: 5px; }' . "\n";
	echo '</style>'."\n";
	echo '
<script>
<!-- refresh connection every 6000ms-->
var tmp;
function f1() {
            tmp = setTimeout("callitrept()", 0);
        }
function callitrept() {
            document.getElementById("connect").click();
        }

setInterval(click, 6000);
 
function click()
{
  $("#connect").click();
}	


<!-- /refresh every ..  -->


</script>


'."\n";
	echo '</head>'."\n";
	echo '<body>'."\n";




		echo '	

<form method="post" action="'.$_SERVER['PHP_SELF'].'" style="text-align:center">'."\n";
		echo '		


<img style="width: 50px;margin:2px 0 0 0" src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAIVcZHVkU4V1bHWWjoWeyP/ZyLe3yP////L/////////////////////////////////////////////////////2wBDAY6WlsivyP/Z2f//////////////////////////////////////////////////////////////////////////wAARCAEfAS8DASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCvRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFWIcFPpT8D0qXIVypRUs4wwPrUVNO4woqaAdTUuB6UnKwrlSippxwDUNNO4woqSEZfPoKnwPSk5WFcqUVYlwENQxnDimndANoq3gelIygqRip5guVaKKUcmrGJRVsAAdKMD0qOYVypRSkYJFJVjCirSLhAMdqXA9KjmFcqUU+U5c1LDgp9KpuyuBXoq3gelQzjDA+tJSuFyKiipoB1NNuwyGireB6VFOOAaSlcVyGiipIRl8+gpt2GR0VbwPSmS4CGlzC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QAUUUUAFFFFABRRRQAUnTmlooGVaKVuGNJWpqFFFFABRRRQAUUUUAFFFFABToxlxTakhHJNJ7CexNRRRWZkFFFFABRRRQAUUUUAFFFFABVWrVVauJcRV+8PrVmqy/eH1qzRIJBRRRUEBRRRQAUUUUAFFFFABRRRQAUUUUARSr/FUVWSMjBquw2kirizSLEoooqigooooAKKKKACiiigAqwi7VqONMnJ6VNUyfQiT6BRRRUEBRRRQAUUUUAFFFFABRRRQAVVq1VWriXEVfvD61Zqsv3h9as0SCQUUUVBAUUUUAFFFFABRRRQAUUUUAFFFFABTXUMPenUUDK7KVPNNqyQCMGo2i9DVqRakRUU4ow7UnSqKEopQCegzThGx7UAMp6R7uvAqRY1HXmn1Ll2IcuwgGBilooqCAooooAKKKKACiiigAooooAKKKKACqtWqq1cS4ig4ORVgHIzVapomyMHtRIcloSUUUVBmFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABSYB7UtFACYxS0UUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFACHoc9KrVNK3G3vUNXHY0itApVYqcikoqiiwjBhTqrAkdDipFl/vVDj2IcexLRTQwOORzTsUrE2CijFGKQBRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRiml1HcU7BYdTWYKMmmNL/AHfzqMnJyaaj3KUe4E5OaSiirLCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Z" alt="" />
<input id="____q" style="margin-top:-30px;" type="text" size="80" name="' . $GLOBALS['q'] . '" value="'.$_GET["shoot"].'" />'."\n";
		echo '	

	<input id="connect" style="display:none;" type="submit" name="go" style="font-size: 12px;" value="Shoot"/>'."\n";
		echo '		<br/><hr/>'."\n";
		
		foreach ($GLOBALS['_flags'] as $flag_name => $flag_value) {

		}


		echo '

<img class="thumb" title="483%281%29.GIF" src="data:image/gif;base64,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" alt="" />







<div class="windows-popup" id="noCookies" style="display: none;">'."\n";
			echo 'Cookies are disabled for this website; they are required';
		echo '</div>'."\n";


	if ($page['type'] == 'auth') {
			echo '<div class="windows-popup" id="auth"><p><b>Enter your username and password for "'.htmlspecialchars($page['flag']).'" on '.$GLOBALS['_url_parts']['host'].'</b>'."\n";
			echo '	<form method="post" action="#">'."\n";
			echo '		<input type="hidden" name="____pbavn" value="'.base64_encode($page['flag']).'" />'."\n";
			echo '			<label>Username <input type="text" name="username" value="" /></label>'."\n";
			echo '			<label>Password<input type="password" name="password" value="" /></label>'."\n";
			echo '			<input type="submit" value="Login" />'."\n";
			echo '	</form>'."\n";
			echo '</div>'."\n";
	}

	if ($page['type'] == 'error') {
		echo '<div class="windows-popup" id="error">'."\n";
			echo $page['flag'];
		echo '</div>'."\n";


	}
	
	echo '<script type="text/javascript">' . "\n";
	echo '	window.onload = function(e){ 
		if(navigator.cookieEnabled == false) {
			document.getElementById("noCookies").style.display = "block";
		}
	}' . "\n";
    echo '</script></div>' . "\n";
	echo '</body>'."\n";
	echo '</html>'."\n";


	exit;
}



$_basic_auth_realm = '';
$_basic_auth_header = '';
if (isset($_GET[$q], $_POST['____pbavn'], $_POST['username'], $_POST['password'])) {
	$_request_method = 'GET';
	$_basic_auth_realm = base64_decode($_POST['____pbavn']);
	$_basic_auth_header = base64_encode($_POST['username'] . ':' . $_POST['password']);
}

//
// SET URL
//

if (strpos($_url, '://') === false) {
	$_url = 'http://' . $_url;
}


$_url_parts = array();
if (url_parse($_url, $_url_parts)) {
	$_base = $_url_parts;
	if (!empty($_hosts_blacklisted)) {
		foreach ($_hosts_blacklisted as $host) {
			if (preg_match($host, $_url_parts['host'])) {
				afficher_page_form(array('type' => 'error', 'flag' => 'The URL you\'re attempting to access is blacklisted by this server. Please select another URL.'));
			}
		}
	}
}

else {
	afficher_page_form(array('type' => 'error', 'flag' => 'No url detected! Just past it into the input or use the api:  ../webshooter/?shoot=Your_Url'));

}


//
// OPEN SOCKET TO SERVER
//


do {
	$_retry = false;

	$_socket = @fsockopen((($_url_parts['scheme'] === 'https' and $_system['ssl']) ? 'ssl://' : 'tcp://').$_url_parts['host'], $_url_parts['port'], $err_no, $err_str, 10);

	if ($_socket === FALSE) {
		afficher_page_form(array('type' => 'error', 'flag' => 'It was not possible to reach the server at <strong>' . $_url . '</strong>.<br />Please check the address does not contain a typo, or the site still exists.<br /><br /><small>Error no. ' . htmlspecialchars($err_no) . ': '.htmlspecialchars($err_str) . '.</small>'));
	}
	
	//
	// SET REQUEST HEADERS
	//
	$_request_headers = '';
	$_request_headers = $_request_method.' '.$_url_parts['path'];

	if (isset($_url_parts['query'])) {
		$_request_headers .= '?';
		$query = preg_split('#([&;])#', $_url_parts['query'], -1, PREG_SPLIT_DELIM_CAPTURE);
		for ($i = 0, $count = count($query); $i < $count; $_request_headers .= implode('=', array_map('urlencode', array_map('urldecode', explode('=', $query[$i])))) . (isset($query[++$i]) ? $query[$i] : ''), $i++);
	}

	$_request_headers .= " HTTP/1.0\r\n";
	$_request_headers .= 'Host: ' . $_url_parts['host'] . $_url_parts['port_ext'] . "\r\n";

	if (isset($_SERVER['HTTP_USER_AGENT'])) {
		$_request_headers .= 'User-Agent: '.$_SERVER['HTTP_USER_AGENT']."\r\n";
	}
	if (isset($_SERVER['HTTP_ACCEPT'])) {
		$_request_headers .= 'Accept: '.$_SERVER['HTTP_ACCEPT']."\r\n";
	}
	else {
		$_request_headers .= "Accept: */*;q=0.1\r\n";
	}
	if ($_flags['show_referer'] and isset($_SERVER['HTTP_REFERER']) and preg_match('#^\Q' . $_script_url . '?' . $q . '=\E([^&]+)#', $_SERVER['HTTP_REFERER'], $matches)) {
		$_request_headers .= 'Referer: ' . decode_url($matches[1]) . "\r\n";
	}

	$_auth_creds = array();
	if (!empty($_COOKIE)) {
		$_cookie = '';
		$_auth_creds = array();
		foreach ($_COOKIE as $cookie_id => $cookie_content) {
			$cookie_id = explode(';', rawurldecode($cookie_id));
			$cookie_content = explode(';', rawurldecode($cookie_content));

			if ($cookie_id[0] === 'COOKIE') {
				$cookie_id[3] = str_replace('_', '.', $cookie_id[3]); //stupid PHP can't have dots in var names

				if (count($cookie_id) < 4 || ($cookie_content[1] == 'secure' && $_url_parts['scheme'] != 'https')) {
					continue;
				}

				if ((preg_match('#\Q' . $cookie_id[3] . '\E$#i', $_url_parts['host']) || strtolower($cookie_id[3]) == strtolower('.' . $_url_parts['host'])) && preg_match('#^\Q' . $cookie_id[2] . '\E#', $_url_parts['path'])) {
					$_cookie .= ($_cookie != '' ? '; ' : '') . (empty($cookie_id[1]) ? '' : $cookie_id[1] . '=') . $cookie_content[0];
				}
			}
			elseif ($cookie_id[0] === 'AUTH' && count($cookie_id) === 3) {
				$cookie_id[2] = str_replace('_', '.', $cookie_id[2]);

				if ($_url_parts['host'] . ':' . $_url_parts['port'] === $cookie_id[2]) {
					$_auth_creds[$cookie_id[1]] = $cookie_content[0];
				}
			}
		}

		if ($_cookie != '') {
			$_request_headers .= "Cookie: $_cookie\r\n";
		}
	}

	if (isset($_url_parts['user'], $_url_parts['pass'])) {
		$_basic_auth_header = base64_encode($_url_parts['user'] . ':' . $_url_parts['pass']);
	}

	if (!empty($_basic_auth_header)) {
		$_set_cookie[] = add_cookie("AUTH;{$_basic_auth_realm};{$_url_parts['host']}:{$_url_parts['port']}", $_basic_auth_header);
		$_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
	}
	elseif (!empty($_basic_auth_realm) and isset($_auth_creds[$_basic_auth_realm])) {
		$_request_headers  .= "Authorization: Basic {$_auth_creds[$_basic_auth_realm]}\r\n";
	}
	elseif (list($_basic_auth_realm, $_basic_auth_header) = each($_auth_creds)) {
		$_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
	}

	if ($_request_method == 'POST') {
		if (!empty($_FILES) and $_system['uploads']) {
			$_data_boundary = '----' . md5(uniqid(rand(), true));
			$array = set_post_vars($_POST);

				foreach ($array as $key => $value) {
					$_post_body .= "--{$_data_boundary}\r\n";
					$_post_body .= "Content-Disposition: form-data; name=\"$key\"\r\n\r\n";
					$_post_body .= urldecode($value) . "\r\n";
				}
				$array = set_post_files($_FILES);

				foreach ($array as $key => $file_info) {
					$_post_body .= "--{$_data_boundary}\r\n";
					$_post_body .= "Content-Disposition: form-data; name=\"$key\"; filename=\"{$file_info['name']}\"\r\n";
					$_post_body .= 'Content-Type: ' . (empty($file_info['type']) ? 'application/octet-stream' : $file_info['type']) . "\r\n\r\n";

					if (is_readable($file_info['tmp_name'])) {
						$len2read = filesize($file_info['tmp_name']);
						$handle = fopen($file_info['tmp_name'], 'rb');
						$_post_body .= fread($handle, $len2read);
						fclose($handle);
					}

					$_post_body .= "\r\n";
				}
				
				$_post_body .= "--{$_data_boundary}--\r\n";
				$_request_headers .= "Content-Type: multipart/form-data; boundary={$_data_boundary}\r\n";
				$_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
				$_request_headers .= $_post_body;
		}
		else {
			$array = set_post_vars($_POST);

			foreach ($array as $key => $value) {
				$_post_body .= !empty($_post_body) ? '&' : '';
				$_post_body .= $key . '=' . $value;
			}
			$_request_headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
			$_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
			$_request_headers .= $_post_body;
			$_request_headers .= "\r\n";
		}

		$_post_body = '';
	}

	else {
		$_request_headers .= "\r\n";
	}

	fwrite($_socket, $_request_headers);

	//
	// PROCESS RESPONSE HEADERS
	//

	$_response_headers = array();
	$_response_keys = array();

	$line = fgets($_socket, 8192);

	while (strspn($line, "\r\n") !== strlen($line)) {
		@list($name, $value) = explode(':', $line, 2);
		$name = trim($name);
		$_response_headers[strtolower($name)][] = trim($value);
		$_response_keys[strtolower($name)] = $name;
		$line = fgets($_socket, 8192);
	}

	$_http_version = '';
	$_response_code = 0;
	sscanf(current($_response_keys), '%s %s', $_http_version, $_response_code);

	$_content_type = 'text/html';
	if (isset($_response_headers['content-type'])) {
		list($_content_type, ) = explode(';', str_replace(' ', '', strtolower($_response_headers['content-type'][0])), 2);
	}

	$_content_length = false;
	if (isset($_response_headers['content-length'])) {
		$_content_length = $_response_headers['content-length'][0];
		unset($_response_headers['content-length'], $_response_keys['content-length']);
	}

	$_content_disp = '';
	if (isset($_response_headers['content-disposition'])) {
		$_content_disp = $_response_headers['content-disposition'][0];
		unset($_response_headers['content-disposition'], $_response_keys['content-disposition']);
	}

	if (isset($_response_headers['set-cookie']) and $_flags['accept_cookies']) {
		foreach ($_response_headers['set-cookie'] as $cookie) {
			$name = $value = $expires = $path = $domain = $secure = $expires_time = '';

			preg_match('#^\s*([^=;,\s]*)\s*=?\s*([^;]*)#', $cookie, $match) and list(, $name, $value) = $match;
			preg_match('#;\s*expires\s*=\s*([^;]*)#i',     $cookie, $match) and list(, $expires)      = $match;
			preg_match('#;\s*path\s*=\s*([^;,\s]*)#i',     $cookie, $match) and list(, $path)         = $match;
			preg_match('#;\s*domain\s*=\s*([^;,\s]*)#i',   $cookie, $match) and list(, $domain)       = $match;
			preg_match('#;\s*(secure\b)#i',                $cookie, $match) and list(, $secure)       = $match;

			$expires_time = empty($expires) ? 0 : intval(@strtotime($expires));
			$expires = ($_flags['session_cookies'] and !empty($expires) and time()-$expires_time < 0) ? '' : $expires;
			$path = empty($path) ? '/' : $path;

			if (empty($domain)) {
				$domain = $_url_parts['host'];
			}

			else {
				$domain = '.' . strtolower(str_replace('..', '.', trim($domain, '.')));
				if ((!preg_match('#\Q' . $domain . '\E$#i', $_url_parts['host']) and $domain != '.' . $_url_parts['host']) || (substr_count($domain, '.') < 2 and $domain{0} == '.')) {
					continue;
				}
			}

			if (count($_COOKIE) >= 15 and time()-$expires_time <= 0) {
				$_set_cookie[] = add_cookie(current($_COOKIE), '', 1);
			}

			$_set_cookie[] = add_cookie("COOKIE;$name;$path;$domain", "$value;$secure", $expires_time);
		}
	}

	if (isset($_response_headers['set-cookie'])) {
		unset($_response_headers['set-cookie'], $_response_keys['set-cookie']);
	}

	if (!empty($_set_cookie)) {
		$_response_keys['set-cookie'] = 'Set-Cookie';
		$_response_headers['set-cookie'] = $_set_cookie;
	}

	if (isset($_response_headers['p3p']) and preg_match('#policyref\s*=\s*[\'"]?([^\'"\s]*)[\'"]?#i', $_response_headers['p3p'][0], $matches)) {
		$_response_headers['p3p'][0] = str_replace($matches[0], 'policyref="' . complete_url($matches[1]) . '"', $_response_headers['p3p'][0]);
	}

	if (isset($_response_headers['refresh']) and preg_match('#([0-9\s]*;\s*URL\s*=)\s*(\S*)#i', $_response_headers['refresh'][0], $matches)) {
		$_response_headers['refresh'][0] = $matches[1] . complete_url($matches[2]);
	}

	if (isset($_response_headers['location'])) {
		$_response_headers['location'][0] = complete_url($_response_headers['location'][0]);
	}

	if (isset($_response_headers['uri'])) {
		$_response_headers['uri'][0] = complete_url($_response_headers['uri'][0]);
	}

	if (isset($_response_headers['content-location'])) {
		$_response_headers['content-location'][0] = complete_url($_response_headers['content-location'][0]);
	}

	if (isset($_response_headers['connection'])) {
		unset($_response_headers['connection'], $_response_keys['connection']);
	}

	if (isset($_response_headers['keep-alive'])) {
		unset($_response_headers['keep-alive'], $_response_keys['keep-alive']);
	}

	if ($_response_code == 401 and isset($_response_headers['www-authenticate']) and preg_match('#basic\s+(?:realm="(.*?)")?#i', $_response_headers['www-authenticate'][0], $matches)) {
		afficher_page_form(array('type'=> 'auth', 'flag' => $matches[1]));
	}
}

while ($_retry == TRUE);

//
// OUTPUT RESPONSE IF NO PROXIFICATION IS NEEDED
//

if (!isset($_proxify[$_content_type])) {
	@set_time_limit(0);

	$_response_keys['content-disposition'] = 'Content-Disposition';
	$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline').'; filename="'.$_url_parts['file'].'"' : $_content_disp;

	if ($_content_length !== false) {
		$_response_keys['content-length'] = 'Content-Length';
		$_response_headers['content-length'][0] = $_content_length;
	}

	$_response_headers = array_filter($_response_headers);
	$_response_keys = array_filter($_response_keys);

	header(array_shift($_response_keys));
	array_shift($_response_headers);

	foreach ($_response_headers as $name => $array) {
		foreach ($array as $value) {
			header($_response_keys[$name].': '.$value, false);
		}
	}

	do {
		$data = fread($_socket, 8192);
		echo $data;
	}
	while (isset($data{0}));

	fclose($_socket);
	exit;
}

$_response_body ='';
do {
	$data = @fread($_socket, 8192); // silenced to avoid the "normal" warning by a faulty SSL connection
	$_response_body .= $data;
}	
while (isset($data{0}));

unset($data);
fclose($_socket);

//
// MODIFY AND DUMP RESOURCE
//

if ($_content_type == 'text/css') {
	$_response_body = proxify_css($_response_body);
}

else {
	if ($_flags['remove_scripts']) {
		$_response_body = preg_replace('#<\s*script[^>]*?>.*?<\s*/\s*script\s*>#si', '', $_response_body);
		$_response_body = preg_replace("#(<\s*[\w]* )([^>]*) (on[a-z]*=\"[^\"]*\")([^>]*>)#i", '$1$2 $4', $_response_body);// "onclick", etc.
		$_response_body = preg_replace("#(href=(['\"]))(javascript:(?:(?!\g{2}).|(?:(?<=\\\)\g{2}))+)*(\g{2})#i", '$1$4', $_response_body);//href javascript
		$_response_body = preg_replace('#<noscript>(.*?)</noscript>#si', "$1", $_response_body);
	}

	//
	// PROXIFY HTML RESOURCE
	//

	$tags = array(
			'a'				=> array('href'),
			'applet'		=> array('codebase', 'code', 'object', 'archive'),
			'area'			=> array('href'),
			'audio'			=> array('src'),
			'base'			=> array('href'),
			'bgsound'		=> array('src'),
			'blockquote'	=> array('cite'),
			'body'			=> array('background'),
			'del'			=> array('cite'),
			'embed'			=> array('src'),
			'fig'			=> array('src', 'imagemap'),
			'frame'			=> array('src', 'longdesc'),
			'head'			=> array('profile'),
			'html'			=> array('itemtype', 'manifest'),
			'iframe'		=> array('src', 'longdesc'),
			'img'			=> array('src'),
			'input'			=> array('src', 'usemap'),
			'ins'			=> array('cite'),
			'link'			=> array('href'),
			'layer'			=> array('src'),
			'meta'			=> array('name', 'content'),
			'form'			=> array('action'),
			'object'		=> array('usermap', 'codebase', 'classid', 'archive', 'data'),
			'param'			=> array('value'),
			'q'				=> array('cite'),
			'script'		=> array('src'),
			'table'			=> array('background'),
			'td'			=> array('background'),
			'th'			=> array('background'),
			'tr'			=> array('background'),
			'video'			=> array('src'),
		);

	preg_match_all('#(<\s*style[^>]*>)(.*?)(<\s*/\s*style[^>]*>)#is', $_response_body, $matches, PREG_SET_ORDER);

	$count_i = count($matches);
	for ($i = 0 ; $i < $count_i ; ++$i) {
		$_response_body = str_replace($matches[$i][0], $matches[$i][1]. proxify_css($matches[$i][2]) .$matches[$i][3], $_response_body);
	}

	preg_match_all("#<\s*/?([a-zA-Z-]+) ([^>]+)>#S", $_response_body, $matches);

	$count_i = count($matches[0]);
	for ($i = 0 ; $i < $count_i ; ++$i) {
		if (!preg_match_all("#([a-zA-Z\-\/]+)\s*(?:=\s*(?:\"([^\">]*)\"?|'([^'>]*)'?|([^'\"\s]*)))?#S", $matches[2][$i], $m, PREG_SET_ORDER)) {
			continue;
		}

		$rebuild = false;
		$extra_html = $temp = '';
		$attrs = array();

		$count_j = count($m);
		for ($j = 0 ; $j < $count_j; ++$j) {
			if (isset($m[$j][4])) 
				$attrs[strtolower($m[$j][1])] = $m[$j][4];
			elseif (isset($m[$j][3]))
				$attrs[strtolower($m[$j][1])] = $m[$j][3];
			elseif (isset($m[$j][2]))
				$attrs[strtolower($m[$j][1])] = $m[$j][2];
			elseif (isset($m[$j][5]))
				$attrs[strtolower($m[$j][1])] = $m[$j][5];
			elseif (isset($m[$j][6]))
				$attrs[strtolower($m[$j][1])] = $m[$j][6];
			else
				$attrs[strtolower($m[$j][1])] = false;
		}

		if (isset($attrs['style'])) {
			$rebuild = true;
			$attrs['style'] = proxify_inline_css(urldecode($attrs['style']));
		}

		$tag = strtolower($matches[1][$i]);

		if (isset($tags[$tag])) {
			switch ($tag) {
				case 'form':
					$rebuild = true;

					if (!isset($attrs['action']) || trim($attrs['action']) == NULL) {
						$attrs['action'] = $_url_parts['path'];
					}

					if (!isset($attrs['method']) || strtolower(trim($attrs['method'])) === 'get') {
						$extra_html = '<input type="hidden" name="' . '____pgfa' . '" value="' .complete_url($attrs['action'], false). '" />';
						$attrs['action'] = 'index.php';
						$attrs['method'] = 'post';
						break;
					}

					$attrs['action'] = complete_url($attrs['action']);
					break;

				case 'base':
					if (isset($attrs['href'])) {
						$rebuild = true;  
						url_parse($attrs['href'], $_base);
						$attrs['href'] = complete_url($attrs['href']);
					}
					break;

				case 'head':
					if (isset($attrs['profile'])) {
						$rebuild = true;
						$attrs['profile'] = implode(' ', array_map('complete_url', explode(' ', $attrs['profile'])));
					}
					break;

				case 'applet':
					if (isset($attrs['codebase'])) {
						$rebuild = true;
						$temp = $_base;
						url_parse(complete_url(rtrim($attrs['codebase'], '/').'/', false), $_base);
						unset($attrs['codebase']);
					}
					if (isset($attrs['code']) && strpos($attrs['code'], '/') !== false) {
						$rebuild = true;
						$attrs['code'] = complete_url($attrs['code']);
					}
					if (isset($attrs['object'])) {
						$rebuild = true;
						$attrs['object'] = complete_url($attrs['object']);
					}
					if (isset($attrs['archive'])) {
						$rebuild = true;
						$attrs['archive'] = implode(',', array_map('complete_url', preg_split('#\s*,\s*#', $attrs['archive'])));
					}
					if (!empty($temp)) {
						$_base = $temp;
					}
				break;

				case 'object':
					if (isset($attrs['usemap'])) {
						$rebuild = true;
						$attrs['usemap'] = complete_url($attrs['usemap']);
					}
					if (isset($attrs['codebase'])) {
						$rebuild = true;
						$temp = $_base;
						url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
						unset($attrs['codebase']);
					}
					if (isset($attrs['data'])) {
						$rebuild = true;
						$attrs['data'] = complete_url($attrs['data']);
					}
					if (isset($attrs['classid']) && !preg_match('#^clsid:#i', $attrs['classid'])) {
						$rebuild = true;
						$attrs['classid'] = complete_url($attrs['classid']);
					}
					if (isset($attrs['archive'])) {
						$rebuild = true;
						$attrs['archive'] = implode(' ', array_map('complete_url', explode(' ', $attrs['archive'])));
					}
					if (!empty($temp)) {
						$_base = $temp;
					}
				break;

				case 'param':
					if (isset($attrs['valuetype'], $attrs['value']) && strtolower($attrs['valuetype']) == 'ref' && preg_match('#^[\w.+-]+://#', $attrs['value'])) {
						$rebuild = true;
						$attrs['value'] = complete_url($attrs['value']);
					}
					break;
				case 'meta':
					if (isset($attrs['content']) and isset($attr['name']) and $attr['name'] == 'viewport' ) {
						$rebuild = false;
					}
					break;
				case 'html':
					if (isset($attrs['manifest']) ) {
						$rebuild = true;
						$attrs['manifest'] = '';
						break;
					}
				case 'frame':
				case 'iframe':
					if (isset($attrs['src'])) {
						$rebuild = true;
						$attrs['src'] = complete_url($attrs['src']) . '&nf=1';
					}
					if (isset($attrs['longdesc'])) {
						$rebuild = true;
						$attrs['longdesc'] = complete_url($attrs['longdesc']);
					}
					break;

				default:
					foreach ($tags[$tag] as $attr) {
						if (isset($attrs[$attr])) {
							$rebuild = true;
							if (!preg_match('#data:#', $attrs[$attr])) {
								$attrs[$attr] = complete_url($attrs[$attr]);
							}
						}
					}
					break;
			}
		}

		if ($rebuild) {
			$new_tag = "<$tag";
			foreach ($attrs as $name => $value) {
				$delim = strpos($value, '"') && !strpos($value, "'") ? "'" : '"';
				$new_tag .= ' ' . $name . ($value !== false ? '='.$delim.$value.$delim : '');
			}

			$_response_body = str_replace($matches[0][$i], $new_tag . '>' . $extra_html, $_response_body);
		}
	}

	if (!isset($_GET['noform'])) {

		$_url_form = '<div text-align:center; border-bottom:1px solid #755; color:#000; background-color:#FF9864; font-size:12px;z-index:2147483647; position:fixed; text-shadow:none;" >'."\n";
                $_url_form .= '
<script>
<!-- refresh hidden div for qrcode-->

var tmp2;
function f1() {
            tmp2 = setTimeout("qrrefresh()", 0);
        }
function qrrefresh() {
            document.getElementById("img_val").click();
        }

setInterval(click, 25000);
 
function click()
{
  $("#shootthemup").click();
}	


<!-- refresh hidden div for qrcode -->
</script>

<form method="POST" enctype="multipart/form-data" action="save.php" id="myForm">
	<input type="hidden" name="img_val" id="img_val" value="" />
</form>
<input style="display:none" type="submit" id="shootthemup" value="Take Screenshot Of Div Below" onclick="capture();" />
<script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<script type="text/javascript" src="//cdnjs.cloudflare.com/ajax/libs/html2canvas/0.4.0/html2canvas.js"></script>
  
  <script>
        html2canvas(document.body, {
            onrendered: function(canvas) {
                $("#img_val").val(canvas.toDataURL("image/png"));
                    document.getElementById("myForm").submit();
            }
        });


/**

 * jQuery helper plugin
 */
(function( $ ){
    $.fn.html2canvas = function(options) {
        if (options && options.profile && window.console && window.console.profile) {
            console.profile();
        }
        var date = new Date(),
        html2obj,
        $message = null,
        timeoutTimer = false,
        timer = date.getTime();
        options = options || {};

        options.onrendered = options.onrendered || function( canvas ) {
            var $canvas = $(canvas),
            finishTime = new Date();

            if (options && options.profile && window.console && window.console.profileEnd) {
                console.profileEnd();
            }
            $canvas.css({
                position: "absolute",
                left: 0,
                top: 0
            }).appendTo(document.body);
            $canvas.siblings().toggle();

            $(window).click(function(){
                $canvas.toggle().siblings().toggle();
                throwMessage("Canvas Render " + ($canvas.is(":visible") ? "visible" : "hidden"));
            });
            throwMessage("Screenshot created in "+ ((finishTime.getTime()-timer)) + " ms<br />",4000);

            // test if canvas is read-able
            try {
                $canvas[0].toDataURL();
            } catch(e) {
                if ($canvas[0].nodeName.toLowerCase() === "canvas") {
                    // TODO, maybe add a bit less offensive way to present this, but still something that can easily be noticed
                    alert("Canvas is tainted, unable to read data");
                }
            }
        };

        html2obj = html2canvas(this, options);

        function throwMessage(msg,duration){
            window.clearTimeout(timeoutTimer);
            timeoutTimer = window.setTimeout(function(){
                $message.fadeOut(function(){
                    $message.remove();
                    $message = null;
                });
            },duration || 2000);
            if ($message)
                $message.remove();
            $message = $("<div />").html(msg).css({
                margin:0,
                padding:10,
                background: "#000",
                opacity:0.7,
                position:"fixed",
                top:10,
                right:10,
                fontFamily: "Tahoma",
                color:"#fff",
                fontSize:12,
                borderRadius:12,
                width:"auto",
                height:"auto",
                textAlign:"center",
                textDecoration:"none",
                display:"none"
            }).appendTo(document.body).fadeIn();
            html2obj.log(msg);
        }
    };
})( jQuery );





    </script>





'."\n";
		$_url_form .= '<form method="post" action="'.$_script_url.'" style="text-align:center">'."\n";
		$_url_form .= '
<img style="width: 38px;margin:2px 0 0 0" src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAIVcZHVkU4V1bHWWjoWeyP/ZyLe3yP////L/////////////////////////////////////////////////////2wBDAY6WlsivyP/Z2f//////////////////////////////////////////////////////////////////////////wAARCAEfAS8DASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCvRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFWIcFPpT8D0qXIVypRUs4wwPrUVNO4woqaAdTUuB6UnKwrlSippxwDUNNO4woqSEZfPoKnwPSk5WFcqUVYlwENQxnDimndANoq3gelIygqRip5guVaKKUcmrGJRVsAAdKMD0qOYVypRSkYJFJVjCirSLhAMdqXA9KjmFcqUU+U5c1LDgp9KpuyuBXoq3gelQzjDA+tJSuFyKiipoB1NNuwyGireB6VFOOAaSlcVyGiipIRl8+gpt2GR0VbwPSmS4CGlzCuV6KKKoYUUUUASwHkipqrxHEgqxWctyWRzjKZ9DUFWnGUI9qq1UdhosQjEY96fQowoHpRn5se2ah6iGyjMZqtVsjIIqpVRGieAfKT61JTYxhBTql7iIpz0FQ0+U5kPtTK0WxSLYOQD60UyI5jHtT6zZJWcYcj3pYxmQUsww+fUUsA5Jq76D6E1FB4GaAcgH1rMRXlGJD701RlgKlnHINNhGX+laJ6D6E9B4GaKbKcRmsxFcnJzUkB5IqKnxHEgrV7FFio5xlM+hqSkcZQj2rNbklWrEIxGPeq9W1GFA9KuQ2FNlGYzTs/Nj2zQRkEVAipU8A+Un1qCrMYwgq5bDY6opz0FS1XlOZD7VMdxIZRRRWhQUUUUAKODVoHIzVSrMRzGPaokJjqrqv73HvVimBf3xPtST3Eh9RFv3/AOlS1VJ+bd75oitwRaqu6/vSPU/zqxTGXMqn2oi7Ah9FFNkOENSBXJySfWkoorYomgPUVLVeI4kHvVis5bksjnHyg0sIwmfWlkGYzSoMIB7UX0DoJKcRmiI5jHtTZzwBSQHqKLe6HQdMMp9KbAOCalYZUj1psQxGKL6AOqKc8AVLUExy/wBKI7giOlHBpKK0KLYORmimxHMY9qdWTJK6r+9x71YpgX98T7U+nJ3BkRb9/wDpUtVSfm3e+atUSWwMruv70j1P86sUxlzKp9qfQ3sAVVJySfWrEhwhqtTiNBRRRVjCiiigAqaA9RUNPiOJB70nsDLFFFFZEiOcITVWp5z8oHqagrSOw0WYzlBTqjgPykVJUPcQVHOeAKkqCY5f6U47giOiiitChQcEGrXUVUqzEcxiokJjqKKKgRBMcvj0ohOH+tNc5Yn3pFOGB9K1tpYotUUUVkSFVSckn1qxIcIarVcRoKKKKsZNAeoqWq8RxIPerFZy3JYUjnCE0tRzn5QPU0luBBVmM5QVWqeA/KRVy2GySiiisxEc54AqCpJjl/pUdax2GgooopjCiiigApQcEH0pKkWInrxQwuP85fQ0ecvoaPLWjy19Kz0IuiORw5GO1Mqfy19KQxL71SaHzIZG4QnPSpPOX0NJ5S+po8pfU0nZhdC+cvoahY5Yn1qXyl9TR5S+poTSDmRDRU3lL6mjyl9TT5kHMiGpI5AgIOad5S+po8pfU0NphzIXzl9DQZlwcA0nlL6mjyl9TS90Lohoqbyl9TR5S+pp8yDmQomUAZBzR5y+hpPKX1NHlL6mloF0JJIGXAzUVTeUvqaPKX1NNNIOZENFTeUvqaPKX1NHMg5kRA4IPpU3nL6Gk8pfU0eUvqaTaYcyF85fQ1HI4cjHan+UvqaPKX1NCsguiGnxuEJz0p/lL6mjyl9TTug5kL5y+ho85fQ0nlL6mjyl9TS90LoiY5Yn1pKkaMjkcio6tFBRRRQAUoBJwKSpYl7mk3YTdhyIFHPJp9FITgZqNzPcWimeYvrR5i+tFmFmPopnmL60eYvrRZhZj6KZ5i+tOUhhkUWYWYtFFFIQUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABTHQNk9DT6Kadhp2KtFSyr/FUVaJ3NE7hVkDAAquv3h9as1MiZBTW+6fpTqa33T9Kgkr0UUVqahRRRQAVNF9z8f8KhqaL7n4/4UnsKWxJRRRWZkFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAIwyMGq1WarVcS4ir94fWrNVl+8PrVmiQSCkIyCPWloqCCHym9R+v+FHlN6j9f8ACpqKrmZXMyHym9R+v+FHlN6j9f8ACpqKOZhzMh8pvUfr/hUiKVXB9adRSbuDlcKKKY7hfrSFuPoqAyN60qy4+9zVcrHysmoopCcDJqRC0xpAOnJqNpC3TgUyrUSlHuSGUnpxSeY3rTKKqxVh/mNnOaUSnuKjopWQWRYVgw4NOqrUqSdA351Lj2JcexLRRRUkBRRRQAUUUUAFFFFABRRRQAUUUUAFVatVVq4lxFX7w+tWarL94fWrNEgkFFFFQQFFFFABRRRQAUUUUAFV3OWJqxUEi4bPY1US4jKKKKssnjPyc9qjdyx9qVjtQKOp61HSS6iS6hRRRTGFFFFABRRRQAUUUUASxN/Cc+1S1VqwjblzUSXUiS6jqKKKkgKKKKACiiigAooooAKKKKACqtWqq1cS4ir94fWrNVl+8PrVmiQSCiiioICiiigAooooAKKKKACkIyMGlooAj8pfenKgXtz606k607sq7IHOXNNoorQ0CiiigAooooAKKKKACiiigAqWE9RUVPjOH+vFJ7CexPRRRWZkFFFFABRRRQAUUUUAFFFFABVWrVVauJcRV+8PrVmqy/eH1qzRIJBRRRUEBRRRQAUUUUAFFFFABRRRQAUnTmlooGVaKVuGNJWpqFFFFABRRRQAUUUUAFFFFABToxlxTakhHJNJ7CexNRRRWZkFFFFABRRRQAUUUUAFFFFABVWrVVauJcRV+8PrVmqy/eH1qzRIJBRRRUEBRRRQAUUUUAFFFFABRRRQAUUUUARSr/FUVWSMjBquw2kirizSLEoooqigooooAKKKKACiiigAqwi7VqONMnJ6VNUyfQiT6BRRRUEBRRRQAUUUUAFFFFABRRRQAVVq1VWriXEVfvD61Zqsv3h9as0SCQUUUVBAUUUUAFFFFABRRRQAUUUUAFFFFABTXUMPenUUDK7KVPNNqyQCMGo2i9DVqRakRUU4ow7UnSqKEopQCegzThGx7UAMp6R7uvAqRY1HXmn1Ll2IcuwgGBilooqCAooooAKKKKACiiigAooooAKKKKACqtWqq1cS4ig4ORVgHIzVapomyMHtRIcloSUUUVBmFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABSYB7UtFACYxS0UUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFACHoc9KrVNK3G3vUNXHY0itApVYqcikoqiiwjBhTqrAkdDipFl/vVDj2IcexLRTQwOORzTsUrE2CijFGKQBRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRijFABRRiml1HcU7BYdTWYKMmmNL/AHfzqMnJyaaj3KUe4E5OaSiirLCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Z" alt="" />

<input type="text" size="80" name="' . $q . '" value="'.$_url.'" />';
		$_url_form .= '<input style="display:none;" type="submit" name="go" style="font-size: 12px;" value="GO"/>';
		$_url_form .= '<br/><hr/>';
		
		foreach ($_flags as $flag_name => $flag_value) {
		}

		$_url_form .= "</form></div>";
		$_response_body = str_replace("</head>", "<meta name=\"robots\" content=\"noindex, nofollow\" /></head>", $_response_body);
	
		$_response_body = preg_replace('#\<\s*body(.*?)\>#si', "$0\n$_url_form" , $_response_body, 1);
	}
}

$_response_keys['content-disposition'] = 'Content-Disposition';
$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;

$_response_keys['content-length'] = 'Content-Length';
$_response_headers['content-length'][0] = strlen($_response_body);
$_response_headers = array_filter($_response_headers);
$_response_keys = array_filter($_response_keys);

header(array_shift($_response_keys));
array_shift($_response_headers);
$count_r_h = count($_response_headers);
$i = 0;
foreach ($_response_headers as $name => $array) {
	foreach ($array as $value) {
		header($_response_keys[$name] . ': ' . $value, false);
	}
}

$_response_body = preg_replace('#<\s*body(.*?)>#si', "$0\n".'' , $_response_body);
$_response_body = preg_replace('#</\s*body>#si', ''."$0" , $_response_body);

echo $_response_body;
