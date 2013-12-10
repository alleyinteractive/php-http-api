<?php

require_once( dirname( __FILE__ ) . '/class-http.php' );

/**
 * Simple and uniform HTTP request API.
 */

/**
 * Returns the initialized Http Object
 *
 * @access private
 *
 * @return Http HTTP Transport object.
 */
function _http_get_object() {
	static $http;

	if ( is_null($http) )
		$http = new Http();

	return $http;
}

/**
 * Retrieve the raw response from the HTTP request.
 *
 * The array structure is a little complex.
 *
 * <code>
 * $res = array( 'headers' => array(), 'response' => array('code' => int, 'message' => string) );
 * </code>
 *
 * All of the headers in $res['headers'] are with the name as the key and the
 * value as the value. So to get the User-Agent, you would do the following.
 *
 * <code>
 * $user_agent = $res['headers']['user-agent'];
 * </code>
 *
 * The body is the raw response content and can be retrieved from $res['body'].
 *
 * This function is called first to make the request and there are other API
 * functions to abstract out the above convoluted setup.
 *
 * List of default arguments:
 * 'method'      => 'GET'
 *  - Default 'GET'  for remote_get()
 *  - Default 'POST' for remote_post()
 *  - Default 'HEAD' for remote_head()
 * 'timeout'     => 5
 * 'redirection' => 5
 * 'httpversion' => '1.0'
 * 'user-agent'  => 'MiniHTTP API 1.0'
 * 'blocking'    => true
 * 'headers'     => array()
 * 'cookies'     => array()
 * 'body'        => null
 * 'compress'    => false,
 * 'decompress'  => true,
 * 'sslverify'   => true,
 * 'stream'      => false,
 * 'filename'    => null
 *
 * @param string $url Site URL to retrieve.
 * @param array $args Optional. Override the defaults.
 * @return array The response.
 */
function remote_request($url, $args = array()) {
	$objFetchSite = _http_get_object();
	return $objFetchSite->request($url, $args);
}

/**
 * Retrieve the raw response from the HTTP request using the GET method.
 *
 * @see remote_request() For more information on the response array format and default arguments.
 *
 * @param string $url Site URL to retrieve.
 * @param array $args Optional. Override the defaults.
 * @return array The response.
 */
function remote_get($url, $args = array()) {
	$objFetchSite = _http_get_object();
	return $objFetchSite->get($url, $args);
}

/**
 * Retrieve the raw response from the HTTP request using the POST method.
 *
 * @see remote_request() For more information on the response array format and default arguments.
 *
 * @param string $url Site URL to retrieve.
 * @param array $args Optional. Override the defaults.
 * @return array The response.
 */
function remote_post($url, $args = array()) {
	$objFetchSite = _http_get_object();
	return $objFetchSite->post($url, $args);
}

/**
 * Retrieve the raw response from the HTTP request using the HEAD method.
 *
 * @see remote_request() For more information on the response array format and default arguments.
 *
 * @param string $url Site URL to retrieve.
 * @param array $args Optional. Override the defaults.
 * @return array The response.
 */
function remote_head($url, $args = array()) {
	$objFetchSite = _http_get_object();
	return $objFetchSite->head($url, $args);
}

/**
 * Retrieve only the headers from the raw response.
 *
 * @param array $response HTTP response.
 * @return array The headers of the response. Empty array if incorrect parameter given.
 */
function remote_retrieve_headers(&$response) {
	if ( ! isset($response['headers']) || ! is_array($response['headers']))
		return array();

	return $response['headers'];
}

/**
 * Retrieve a single header by name from the raw response.
 *
 * @param array $response
 * @param string $header Header name to retrieve value from.
 * @return string The header value. Empty string on if incorrect parameter given, or if the header doesn't exist.
 */
function remote_retrieve_header(&$response, $header) {
	if ( ! isset($response['headers']) || ! is_array($response['headers']))
		return '';

	if ( array_key_exists($header, $response['headers']) )
		return $response['headers'][$header];

	return '';
}

/**
 * Retrieve only the response code from the raw response.
 *
 * Will return an empty array if incorrect parameter value is given.
 *
 * @param array $response HTTP response.
 * @return string the response code. Empty string on incorrect parameter given.
 */
function remote_retrieve_response_code(&$response) {
	if ( ! isset($response['response']) || ! is_array($response['response']))
		return '';

	return $response['response']['code'];
}

/**
 * Retrieve only the response message from the raw response.
 *
 * Will return an empty array if incorrect parameter value is given.
 *
 * @param array $response HTTP response.
 * @return string The response message. Empty string on incorrect parameter given.
 */
function remote_retrieve_response_message(&$response) {
	if ( ! isset($response['response']) || ! is_array($response['response']))
		return '';

	return $response['response']['message'];
}

/**
 * Retrieve only the body from the raw response.
 *
 * @param array $response HTTP response.
 * @return string The body of the response. Empty string if no body or incorrect parameter given.
 */
function remote_retrieve_body(&$response) {
	if ( ! isset($response['body']) )
		return '';

	return $response['body'];
}

/**
 * Determines if there is an HTTP Transport that can process this request.
 *
 * @param array  $capabilities Array of capabilities to test or a remote_request() $args array.
 * @param string $url Optional. If given, will check if the URL requires SSL and adds that requirement to the capabilities array.
 *
 * @return bool
 */
function http_supports( $capabilities = array(), $url = null ) {
	$objFetchSite = _http_get_object();

	$count = count( $capabilities );

	// If we have a numeric $capabilities array, spoof a remote_request() associative $args array
	if ( $count && count( array_filter( array_keys( $capabilities ), 'is_numeric' ) ) == $count ) {
		$capabilities = array_combine( array_values( $capabilities ), array_fill( 0, $count, true ) );
	}

	if ( $url && !isset( $capabilities['ssl'] ) ) {
		$scheme = parse_url( $url, PHP_URL_SCHEME );
		if ( 'https' == $scheme || 'ssl' == $scheme ) {
			$capabilities['ssl'] = true;
		}
	}

	return (bool) $objFetchSite->_get_first_available_transport( $capabilities );
}

/**
 * Get the HTTP Origin of the current request.
 *
 * @return string URL of the origin. Empty string if no origin.
 */
function get_http_origin() {
	$origin = '';
	if ( ! empty ( $_SERVER[ 'HTTP_ORIGIN' ] ) )
		$origin = $_SERVER[ 'HTTP_ORIGIN' ];

	return $origin ;
}

/**
 * Retrieve list of allowed HTTP origins.
 *
 * @return array Array of origin URLs.
 */
function get_allowed_http_origins() {
	return array(
		'http://' . $_SERVER['SERVER_NAME'],
		'https://' . $_SERVER['SERVER_NAME'],
	);
}

/**
 * Determines if the HTTP origin is an authorized one.
 *
 * @param string Origin URL. If not provided, the value of get_http_origin() is used.
 * @return bool True if the origin is allowed. False otherwise.
 */
function is_allowed_http_origin( $origin = null ) {
	$origin_arg = $origin;

	if ( null === $origin )
		$origin = get_http_origin();

	if ( $origin && ! in_array( $origin, get_allowed_http_origins() ) )
		$origin = '';

	return $origin;
}

/**
 * Send Access-Control-Allow-Origin and related headers if the current request
 * is from an allowed origin.
 *
 * If the request is an OPTIONS request, the script exits with either access
 * control headers sent, or a 403 response if the origin is not allowed. For
 * other request methods, you will receive a return value.
 *
 * @return bool|string Returns the origin URL if headers are sent. Returns false
 * if headers are not sent.
 */
function send_origin_headers() {
	$origin = get_http_origin();

	if ( is_allowed_http_origin( $origin ) ) {
		@header( 'Access-Control-Allow-Origin: ' .  $origin );
		@header( 'Access-Control-Allow-Credentials: true' );
		if ( 'OPTIONS' === $_SERVER['REQUEST_METHOD'] )
			exit;
		return $origin;
	}

	if ( 'OPTIONS' === $_SERVER['REQUEST_METHOD'] ) {
		status_header( 403 );
		exit;
	}

	return false;
}

/**
 * Retrieve the description for the HTTP status.
 *
 * @param int $code HTTP status code.
 * @return string Empty string if not found, or description if found.
 */
function get_status_header_desc( $code ) {
	global $header_to_desc;

	$code = intval( $code );

	if ( !isset( $header_to_desc ) ) {
		$header_to_desc = array(
			100 => 'Continue',
			101 => 'Switching Protocols',
			102 => 'Processing',

			200 => 'OK',
			201 => 'Created',
			202 => 'Accepted',
			203 => 'Non-Authoritative Information',
			204 => 'No Content',
			205 => 'Reset Content',
			206 => 'Partial Content',
			207 => 'Multi-Status',
			226 => 'IM Used',

			300 => 'Multiple Choices',
			301 => 'Moved Permanently',
			302 => 'Found',
			303 => 'See Other',
			304 => 'Not Modified',
			305 => 'Use Proxy',
			306 => 'Reserved',
			307 => 'Temporary Redirect',

			400 => 'Bad Request',
			401 => 'Unauthorized',
			402 => 'Payment Required',
			403 => 'Forbidden',
			404 => 'Not Found',
			405 => 'Method Not Allowed',
			406 => 'Not Acceptable',
			407 => 'Proxy Authentication Required',
			408 => 'Request Timeout',
			409 => 'Conflict',
			410 => 'Gone',
			411 => 'Length Required',
			412 => 'Precondition Failed',
			413 => 'Request Entity Too Large',
			414 => 'Request-URI Too Long',
			415 => 'Unsupported Media Type',
			416 => 'Requested Range Not Satisfiable',
			417 => 'Expectation Failed',
			422 => 'Unprocessable Entity',
			423 => 'Locked',
			424 => 'Failed Dependency',
			426 => 'Upgrade Required',

			500 => 'Internal Server Error',
			501 => 'Not Implemented',
			502 => 'Bad Gateway',
			503 => 'Service Unavailable',
			504 => 'Gateway Timeout',
			505 => 'HTTP Version Not Supported',
			506 => 'Variant Also Negotiates',
			507 => 'Insufficient Storage',
			510 => 'Not Extended'
		);
	}

	if ( isset( $header_to_desc[$code] ) )
		return $header_to_desc[$code];
	else
		return '';
}

/**
 * Set HTTP status header.
 *
 * @param int $header HTTP status code
 * @return unknown
 */
function status_header( $header ) {
	$text = get_status_header_desc( $header );

	if ( empty( $text ) )
		return false;

	$protocol = $_SERVER["SERVER_PROTOCOL"];
	if ( 'HTTP/1.1' != $protocol && 'HTTP/1.0' != $protocol )
		$protocol = 'HTTP/1.0';
	$status_header = "$protocol $header $text";

	return @header( $status_header, true, $header );
}

