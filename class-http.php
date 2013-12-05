<?php
/**
 * Simple and uniform HTTP request API.
 *
 * Standardizes HTTP requests. Handles cookies, gzip encoding and decoding, chunk
 * decoding, if HTTP 1.1 and various other difficult HTTP protocol implementations.
 */

/**
 * HTTP Class for managing HTTP Transports and making HTTP requests.
 *
 * This class is used to consistently make outgoing HTTP requests easy for developers
 * while still being compatible with the many PHP configurations under which
 * this may run.
 *
 * Debugging includes several actions, which pass different variables for debugging the HTTP API.
 */
class WP_Http {

	/**
	 * Send a HTTP request to a URI.
	 *
	 * The body and headers are part of the arguments. The 'body' argument is for the body and will
	 * accept either a string or an array. The 'headers' argument should be an array, but a string
	 * is acceptable. If the 'body' argument is an array, then it will automatically be escaped
	 * using http_build_query().
	 *
	 * The only URI that are supported in the HTTP Transport implementation are the HTTP and HTTPS
	 * protocols.
	 *
	 * The defaults are 'method', 'timeout', 'redirection', 'httpversion', 'blocking' and
	 * 'user-agent'.
	 *
	 * Accepted 'method' values are 'GET', 'POST', and 'HEAD', some transports technically allow
	 * others, but should not be assumed. The 'timeout' is used to sent how long the connection
	 * should stay open before failing when no response. 'redirection' is used to track how many
	 * redirects were taken and used to sent the amount for other transports, but not all transports
	 * accept setting that value.
	 *
	 * The 'httpversion' option is used to sent the HTTP version and accepted values are '1.0', and
	 * '1.1' and should be a string. The 'user-agent' option is the user-agent and is used to
	 * replace the default user-agent.
	 *
	 * The 'blocking' parameter can be used to specify if the calling code requires the result of
	 * the HTTP request. If set to false, the request will be sent to the remote server, and
	 * processing returned to the calling code immediately, the caller will know if the request
	 * suceeded or failed, but will not receive any response from the remote server.
	 *
	 * @access public
	 *
	 * @param string $url URI resource.
	 * @param str|array $args Optional. Override the defaults.
	 * @return array Array containing 'headers', 'body', 'response', 'cookies', 'filename'.
	 */
	function request( $url, $args = array() ) {
		$defaults = array(
			'method'              => 'GET',
			'timeout'             => 5,
			'redirection'         => 5,
			'httpversion'         => '1.0',
			'user-agent'          => 'MiniHTTP API 1.0',
			'blocking'            => true,
			'headers'             => array(),
			'cookies'             => array(),
			'body'                => null,
			'compress'            => false,
			'decompress'          => true,
			'sslverify'           => true,
			'sslcertificates'     => dirname( __FILE__ ) . '/certificates/ca-bundle.crt',
			'stream'              => false,
			'filename'            => null,
			'limit_response_size' => null,
		);

		// By default, Head requests do not cause redirections.
		if ( isset($args['method']) && 'HEAD' == $args['method'] )
			$defaults['redirection'] = 0;

		$r = array_merge( $defaults, $args );

		// The transports decrement this, store a copy of the original value for loop purposes.
		if ( ! isset( $r['_redirection'] ) )
			$r['_redirection'] = $r['redirection'];

		$arrURL = @parse_url( $url );

		if ( empty( $url ) || empty( $arrURL['scheme'] ) )
			throw new Exception( 'A valid URL was not provided.' );

		// Determine if this is a https call and pass that on to the transport functions
		// so that we can blacklist the transports that do not support ssl verification
		$r['ssl'] = $arrURL['scheme'] == 'https' || $arrURL['scheme'] == 'ssl';

		// If we are streaming to a file but no filename was given drop it in the WP temp dir
		// and pick its name using the basename of the $url
		if ( $r['stream']  && empty( $r['filename'] ) )
			$r['filename'] = '/tmp/' . basename( $url );

		// Force some settings if we are streaming to a file and check for existence and perms of destination directory
		if ( $r['stream'] ) {
			$r['blocking'] = true;
			if ( ! is_writable( dirname( $r['filename'] ) ) )
				throw new Exception( 'Destination directory for file streaming does not exist or is not writable.' );
		}

		if ( is_null( $r['headers'] ) )
			$r['headers'] = array();

		if ( ! is_array( $r['headers'] ) ) {
			$processedHeaders = WP_Http::processHeaders( $r['headers'], $url );
			$r['headers'] = $processedHeaders['headers'];
		}

		if ( isset( $r['headers']['User-Agent'] ) ) {
			$r['user-agent'] = $r['headers']['User-Agent'];
			unset( $r['headers']['User-Agent'] );
		}

		if ( isset( $r['headers']['user-agent'] ) ) {
			$r['user-agent'] = $r['headers']['user-agent'];
			unset( $r['headers']['user-agent'] );
		}

		if ( '1.1' == $r['httpversion'] && !isset( $r['headers']['connection'] ) ) {
			$r['headers']['connection'] = 'close';
		}

		// Construct Cookie: header if any cookies are set
		WP_Http::buildCookieHeader( $r );

		// Avoid issues where mbstring.func_overload is enabled
		$this->mbstring_binary_safe_encoding();

		if ( ! isset( $r['headers']['Accept-Encoding'] ) ) {
			if ( $encoding = WP_Http_Encoding::accept_encoding( $url, $r ) )
				$r['headers']['Accept-Encoding'] = $encoding;
		}

		if ( ( ! is_null( $r['body'] ) && '' != $r['body'] ) || 'POST' == $r['method'] || 'PUT' == $r['method'] ) {
			if ( is_array( $r['body'] ) || is_object( $r['body'] ) ) {
				$r['body'] = http_build_query( $r['body'], null, '&' );

				if ( ! isset( $r['headers']['Content-Type'] ) )
					$r['headers']['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
			}

			if ( '' === $r['body'] )
				$r['body'] = null;

			if ( ! isset( $r['headers']['Content-Length'] ) && ! isset( $r['headers']['content-length'] ) )
				$r['headers']['Content-Length'] = strlen( $r['body'] );
		}

		$response = $this->_dispatch_request( $url, $r );

		$this->mbstring_binary_safe_encoding( true );

		// Append cookies that were used in this request to the response
		if ( ! empty( $r['cookies'] ) ) {
			foreach ( $response['cookies'] as $key => $value ) {
				if ( is_object( $value ) )
					$cookies_set[ $key ] = $value->name;
				else
					$cookies_set[ $key ] = $value['name'];
			}

			foreach ( $r['cookies'] as $cookie ) {
				if ( ! in_array( $cookie->name, $cookies_set ) && $cookie->test( $url ) ) {
					$response['cookies'][] = $cookie;
				}
			}
		}

		return $response;
	}

	/**
	 * Tests which transports are capable of supporting the request.
	 *
	 * @access private
	 *
	 * @param array $args Request arguments
	 * @param string $url URL to Request
	 *
	 * @return string|bool Class name for the first transport that claims to support the request. False if no transport claims to support the request.
	 */
	public function _get_first_available_transport( $args, $url = null ) {
		$request_order = array( 'curl', 'streams' );

		// Loop over each transport on each HTTP request looking for one which will serve this request's needs
		foreach ( $request_order as $transport ) {
			$class = 'WP_HTTP_' . $transport;

			// Check to see if this transport is a possibility, calls the transport statically
			if ( !call_user_func( array( $class, 'test' ), $args, $url ) )
				continue;

			return $class;
		}

		return false;
	}

	/**
	 * Dispatches a HTTP request to a supporting transport.
	 *
	 * Tests each transport in order to find a transport which matches the request arguments.
	 * Also caches the transport instance to be used later.
	 *
	 * The order for requests is cURL, and then PHP Streams.
	 *
	 * @access private
	 *
	 * @param string $url URL to Request
	 * @param array $args Request arguments
	 * @return array Array containing 'headers', 'body', 'response', 'cookies', 'filename'
	 */
	private function _dispatch_request( $url, $args ) {
		static $transports = array();

		$class = $this->_get_first_available_transport( $args, $url );
		if ( !$class )
			throw new Exception( 'There are no HTTP transports available which can complete the requested request.' );

		// Transport claims to support request, instantiate it and give it a whirl.
		if ( empty( $transports[$class] ) )
			$transports[$class] = new $class;

		$response = $transports[$class]->request( $url, $args );

		return $response;
	}

	/**
	 * Uses the POST HTTP method.
	 *
	 * Used for sending data that is expected to be in the body.
	 *
	 * @access public
	 *
	 * @param string $url URI resource.
	 * @param str|array $args Optional. Override the defaults.
	 * @return array Array containing 'headers', 'body', 'response', 'cookies', 'filename'
	 */
	function post($url, $args = array()) {
		$defaults = array('method' => 'POST');
		$r = array_merge( $defaults, $args );
		return $this->request($url, $r);
	}

	/**
	 * Uses the GET HTTP method.
	 *
	 * Used for sending data that is expected to be in the body.
	 *
	 * @access public
	 *
	 * @param string $url URI resource.
	 * @param str|array $args Optional. Override the defaults.
	 * @return array Array containing 'headers', 'body', 'response', 'cookies', 'filename'
	 */
	function get($url, $args = array()) {
		$defaults = array('method' => 'GET');
		$r = array_merge( $defaults, $args );
		return $this->request($url, $r);
	}

	/**
	 * Uses the HEAD HTTP method.
	 *
	 * Used for sending data that is expected to be in the body.
	 *
	 * @access public
	 *
	 * @param string $url URI resource.
	 * @param str|array $args Optional. Override the defaults.
	 * @return array Array containing 'headers', 'body', 'response', 'cookies', 'filename'
	 */
	function head($url, $args = array()) {
		$defaults = array('method' => 'HEAD');
		$r = array_merge( $defaults, $args );
		return $this->request($url, $r);
	}

	/**
	 * Parses the responses and splits the parts into headers and body.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $strResponse The full response string
	 * @return array Array with 'headers' and 'body' keys.
	 */
	public static function processResponse($strResponse) {
		$res = explode("\r\n\r\n", $strResponse, 2);

		return array('headers' => $res[0], 'body' => isset($res[1]) ? $res[1] : '');
	}

	/**
	 * Transform header string into an array.
	 *
	 * If an array is given then it is assumed to be raw header data with numeric keys with the
	 * headers as the values. No headers must be passed that were already processed.
	 *
	 * @access public
	 * @static
	 *
	 * @param string|array $headers
	 * @param string $url The URL that was requested
	 * @return array Processed string headers. If duplicate headers are encountered,
	 * 					Then a numbered array is returned as the value of that header-key.
	 */
	public static function processHeaders( $headers, $url = '' ) {
		// split headers, one per array element
		if ( is_string($headers) ) {
			// tolerate line terminator: CRLF = LF (RFC 2616 19.3)
			$headers = str_replace("\r\n", "\n", $headers);
			// unfold folded header fields. LWS = [CRLF] 1*( SP | HT ) <US-ASCII SP, space (32)>, <US-ASCII HT, horizontal-tab (9)> (RFC 2616 2.2)
			$headers = preg_replace('/\n[ \t]/', ' ', $headers);
			// create the headers array
			$headers = explode("\n", $headers);
		}

		$response = array('code' => 0, 'message' => '');

		// If a redirection has taken place, The headers for each page request may have been passed.
		// In this case, determine the final HTTP header and parse from there.
		for ( $i = count($headers)-1; $i >= 0; $i-- ) {
			if ( !empty($headers[$i]) && false === strpos($headers[$i], ':') ) {
				$headers = array_splice($headers, $i);
				break;
			}
		}

		$cookies = array();
		$newheaders = array();
		foreach ( (array) $headers as $tempheader ) {
			if ( empty($tempheader) )
				continue;

			if ( false === strpos($tempheader, ':') ) {
				$stack = explode(' ', $tempheader, 3);
				$stack[] = '';
				list( , $response['code'], $response['message']) = $stack;
				continue;
			}

			list($key, $value) = explode(':', $tempheader, 2);

			$key = strtolower( $key );
			$value = trim( $value );

			if ( isset( $newheaders[ $key ] ) ) {
				if ( ! is_array( $newheaders[ $key ] ) )
					$newheaders[$key] = array( $newheaders[ $key ] );
				$newheaders[ $key ][] = $value;
			} else {
				$newheaders[ $key ] = $value;
			}
			if ( 'set-cookie' == $key )
				$cookies[] = new WP_Http_Cookie( $value, $url );
		}

		return array('response' => $response, 'headers' => $newheaders, 'cookies' => $cookies);
	}

	/**
	 * Takes the arguments for a ::request() and checks for the cookie array.
	 *
	 * If it's found, then it upgrades any basic name => value pairs to WP_Http_Cookie instances,
	 * which are each parsed into strings and added to the Cookie: header (within the arguments array).
	 * Edits the array by reference.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $r Full array of args passed into ::request()
	 */
	public static function buildCookieHeader( &$r ) {
		if ( ! empty($r['cookies']) ) {
			// Upgrade any name => value cookie pairs to WP_HTTP_Cookie instances
			foreach ( $r['cookies'] as $name => $value ) {
				if ( ! is_object( $value ) )
					$r['cookies'][ $name ] = new WP_HTTP_Cookie( array( 'name' => $name, 'value' => $value ) );
			}

			$cookies_header = '';
			foreach ( (array) $r['cookies'] as $cookie ) {
				$cookies_header .= $cookie->getHeaderValue() . '; ';
			}

			$cookies_header = substr( $cookies_header, 0, -2 );
			$r['headers']['cookie'] = $cookies_header;
		}
	}

	/**
	 * Decodes chunk transfer-encoding, based off the HTTP 1.1 specification.
	 *
	 * Based off the HTTP http_encoding_dechunk function.
	 *
	 * @link http://tools.ietf.org/html/rfc2616#section-19.4.6 Process for chunked decoding.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $body Body content
	 * @return string Chunked decoded body on success or raw body on failure.
	 */
	public static function chunkTransferDecode( $body ) {
		// The body is not chunked encoded or is malformed.
		if ( ! preg_match( '/^([0-9a-f]+)[^\r\n]*\r\n/i', trim( $body ) ) )
			return $body;

		$parsed_body = '';
		$body_original = $body; // We'll be altering $body, so need a backup in case of error

		while ( true ) {
			$has_chunk = (bool) preg_match( '/^([0-9a-f]+)[^\r\n]*\r\n/i', $body, $match );
			if ( ! $has_chunk || empty( $match[1] ) )
				return $body_original;

			$length = hexdec( $match[1] );
			$chunk_length = strlen( $match[0] );

			// Parse out the chunk of data
			$parsed_body .= substr( $body, $chunk_length, $length );

			// Remove the chunk from the raw data
			$body = substr( $body, $length + $chunk_length );

			// End of document
			if ( '0' === trim( $body ) )
				return $parsed_body;
		}
	}


	static function make_absolute_url( $maybe_relative_path, $url ) {
		if ( empty( $url ) )
			return $maybe_relative_path;

		// Check for a scheme
		if ( false !== strpos( $maybe_relative_path, '://' ) )
			return $maybe_relative_path;

		if ( ! $url_parts = @parse_url( $url ) )
			return $maybe_relative_path;

		if ( ! $relative_url_parts = @parse_url( $maybe_relative_path ) )
			return $maybe_relative_path;

		$absolute_path = $url_parts['scheme'] . '://' . $url_parts['host'];
		if ( isset( $url_parts['port'] ) )
			$absolute_path .= ':' . $url_parts['port'];

		// Start off with the Absolute URL path
		$path = ! empty( $url_parts['path'] ) ? $url_parts['path'] : '/';

		// If it's a root-relative path, then great
		if ( ! empty( $relative_url_parts['path'] ) && '/' == $relative_url_parts['path'][0] ) {
			$path = $relative_url_parts['path'];

		// Else it's a relative path
		} elseif ( ! empty( $relative_url_parts['path'] ) ) {
			// Strip off any file components from the absolute path
			$path = substr( $path, 0, strrpos( $path, '/' ) + 1 );

			// Build the new path
			$path .= $relative_url_parts['path'];

			// Strip all /path/../ out of the path
			while ( strpos( $path, '../' ) > 1 ) {
				$path = preg_replace( '![^/]+/\.\./!', '', $path );
			}

			// Strip any final leading ../ from the path
			$path = preg_replace( '!^/(\.\./)+!', '', $path );
		}

		// Add the Query string
		if ( ! empty( $relative_url_parts['query'] ) )
			$path .= '?' . $relative_url_parts['query'];

		return $absolute_path . '/' . ltrim( $path, '/' );
	}

	/**
	 * Handles HTTP Redirects and follows them if appropriate.
	 *
	 * @param string $url The URL which was requested.
	 * @param array $args The Arguements which were used to make the request.
	 * @param array $response The Response of the HTTP request.
	 * @return false|object False if no redirect is present, a WP_HTTP result otherwise.
	 */
	static function handle_redirects( $url, $args, $response ) {
		// If no redirects are present, or, redirects were not requested, perform no action.
		if ( ! isset( $response['headers']['location'] ) || 0 === $args['_redirection'] )
			return false;

		// Only perform redirections on redirection http codes
		if ( $response['response']['code'] > 399 || $response['response']['code'] < 300 )
			return false;

		// Don't redirect if we've run out of redirects
		if ( $args['redirection']-- <= 0 )
			throw new Exception( 'Too many redirects.' );

		$redirect_location = $response['headers']['location'];

		// If there were multiple Location headers, use the last header specified
		if ( is_array( $redirect_location ) )
			$redirect_location = array_pop( $redirect_location );

		$redirect_location = WP_HTTP::make_absolute_url( $redirect_location, $url );

		// POST requests should not POST to a redirected location
		if ( 'POST' == $args['method'] ) {
			if ( in_array( $response['response']['code'], array( 302, 303 ) ) )
				$args['method'] = 'GET';
		}

		// Include valid cookies in the redirect process
		if ( ! empty( $response['cookies'] ) ) {
			foreach ( $response['cookies'] as $cookie ) {
				if ( $cookie->test( $redirect_location ) )
					$args['cookies'][] = $cookie;
			}
		}

		return wp_remote_request( $redirect_location, $args );
	}

	/**
	 * Determines if a specified string represents an IP address or not.
	 *
	 * This function also detects the type of the IP address, returning either
	 * '4' or '6' to represent a IPv4 and IPv6 address respectively.
	 * This does not verify if the IP is a valid IP, only that it appears to be
	 * an IP address.
	 *
	 * @see http://home.deds.nl/~aeron/regex/ for IPv6 regex
	 *
	 * @static
	 *
	 * @param string $maybe_ip A suspected IP address
	 * @return integer|bool Upon success, '4' or '6' to represent a IPv4 or IPv6 address, false upon failure
	 */
	static function is_ip_address( $maybe_ip ) {
		if ( preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $maybe_ip ) )
			return 4;

		if ( false !== strpos( $maybe_ip, ':' ) && preg_match( '/^(((?=.*(::))(?!.*\3.+\3))\3?|([\dA-F]{1,4}(\3|:\b|$)|\2))(?4){5}((?4){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i', trim( $maybe_ip, ' []' ) ) )
			return 6;

		return false;
	}

	/**
	 * Sets the mbstring internal encoding to a binary safe encoding whne func_overload is enabled.
	 *
	 * When mbstring.func_overload is in use for multi-byte encodings, the results from strlen() and
	 * similar functions respect the utf8 characters, causing binary data to return incorrect lengths.
	 *
	 * This function overrides the mbstring encoding to a binary-safe encoding, and resets it to the
	 * users expected encoding afterwards through the `reset_mbstring_encoding` function.
	 *
	 * It is safe to recursively call this function, however each `mbstring_binary_safe_encoding()`
	 * call must be followed up with an equal number of `reset_mbstring_encoding()` calls.
	 *
	 * @see reset_mbstring_encoding()
	 *
	 * @param bool $reset Whether to reset the encoding back to a previously-set encoding.
	 */
	public static function mbstring_binary_safe_encoding( $reset = false ) {
		static $encodings = array();
		static $overloaded = null;

		if ( is_null( $overloaded ) )
			$overloaded = function_exists( 'mb_internal_encoding' ) && ( ini_get( 'mbstring.func_overload' ) & 2 );

		if ( false === $overloaded )
			return;

		if ( ! $reset ) {
			$encoding = mb_internal_encoding();
			array_push( $encodings, $encoding );
			mb_internal_encoding( 'ISO-8859-1' );
		}

		if ( $reset && $encodings ) {
			$encoding = array_pop( $encodings );
			mb_internal_encoding( $encoding );
		}
	}

}

/**
 * HTTP request method uses PHP Streams to retrieve the url.
 */
class WP_Http_Streams {
	/**
	 * Send a HTTP request to a URI using PHP Streams.
	 *
	 * @see WP_Http::request For default options descriptions.
	 *
	 * @access public
	 * @param string $url URI resource.
	 * @param string|array $args Optional. Override the defaults.
	 * @return array 'headers', 'body', 'response', 'cookies' and 'filename' keys.
	 */
	function request($url, $args = array()) {
		$defaults = array(
			'method'      => 'GET',
			'timeout'     => 5,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => array(),
			'body'        => null,
			'cookies'     => array()
		);

		$r = array_merge( $defaults, $args );

		if ( isset($r['headers']['User-Agent']) ) {
			$r['user-agent'] = $r['headers']['User-Agent'];
			unset($r['headers']['User-Agent']);
		} else if ( isset($r['headers']['user-agent']) ) {
			$r['user-agent'] = $r['headers']['user-agent'];
			unset($r['headers']['user-agent']);
		}

		// Construct Cookie: header if any cookies are set
		WP_Http::buildCookieHeader( $r );

		$arrURL = parse_url($url);

		$connect_host = $arrURL['host'];

		$secure_transport = ( $arrURL['scheme'] == 'ssl' || $arrURL['scheme'] == 'https' );
		if ( ! isset( $arrURL['port'] ) ) {
			if ( $arrURL['scheme'] == 'ssl' || $arrURL['scheme'] == 'https' ) {
				$arrURL['port'] = 443;
				$secure_transport = true;
			} else {
				$arrURL['port'] = 80;
			}
		}

		if ( isset( $r['headers']['Host'] ) || isset( $r['headers']['host'] ) ) {
			if ( isset( $r['headers']['Host'] ) )
				$arrURL['host'] = $r['headers']['Host'];
			else
				$arrURL['host'] = $r['headers']['host'];
			unset( $r['headers']['Host'], $r['headers']['host'] );
		}

		// Certain versions of PHP have issues with 'localhost' and IPv6, It attempts to connect to ::1,
		// which fails when the server is not set up for it. For compatibility, always connect to the IPv4 address.
		if ( 'localhost' == strtolower( $connect_host ) )
			$connect_host = '127.0.0.1';

		$connect_host = $secure_transport ? 'ssl://' . $connect_host : 'tcp://' . $connect_host;

		$ssl_verify = isset( $r['sslverify'] ) && $r['sslverify'];

		$proxy = new WP_HTTP_Proxy();

		$context = stream_context_create( array(
			'ssl' => array(
				'verify_peer' => $ssl_verify,
				//'CN_match' => $arrURL['host'], // This is handled by self::verify_ssl_certificate()
				'capture_peer_cert' => $ssl_verify,
				'SNI_enabled' => true,
				'cafile' => $r['sslcertificates'],
				'allow_self_signed' => ! $ssl_verify,
			)
		) );

		$timeout = (int) floor( $r['timeout'] );
		$utimeout = $timeout == $r['timeout'] ? 0 : 1000000 * $r['timeout'] % 1000000;
		$connect_timeout = max( $timeout, 1 );

		$connection_error = null; // Store error number
		$connection_error_str = null; // Store error string

		if ( !WP_DEBUG ) {
			// In the event that the SSL connection fails, silence the many PHP Warnings
			if ( $secure_transport )
				$error_reporting = error_reporting(0);

			if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) )
				$handle = @stream_socket_client( 'tcp://' . $proxy->host() . ':' . $proxy->port(), $connection_error, $connection_error_str, $connect_timeout, STREAM_CLIENT_CONNECT, $context );
			else
				$handle = @stream_socket_client( $connect_host . ':' . $arrURL['port'], $connection_error, $connection_error_str, $connect_timeout, STREAM_CLIENT_CONNECT, $context );

			if ( $secure_transport )
				error_reporting( $error_reporting );

		} else {
			if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) )
				$handle = stream_socket_client( 'tcp://' . $proxy->host() . ':' . $proxy->port(), $connection_error, $connection_error_str, $connect_timeout, STREAM_CLIENT_CONNECT, $context );
			else
				$handle = stream_socket_client( $connect_host . ':' . $arrURL['port'], $connection_error, $connection_error_str, $connect_timeout, STREAM_CLIENT_CONNECT, $context );
		}

		if ( false === $handle ) {
			// SSL connection failed due to expired/invalid cert, or, OpenSSL configuration is broken
			if ( $secure_transport && 0 === $connection_error && '' === $connection_error_str )
				throw new Exception( 'The SSL certificate for the host could not be verified.' );

			throw new Exception($connection_error . ': ' . $connection_error_str );
		}

		// Verify that the SSL certificate is valid for this request
		if ( $secure_transport && $ssl_verify && ! $proxy->is_enabled() ) {
			if ( ! self::verify_ssl_certificate( $handle, $arrURL['host'] ) )
				throw new Exception( 'The SSL certificate for the host could not be verified.' );
		}

		stream_set_timeout( $handle, $timeout, $utimeout );

		if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) ) //Some proxies require full URL in this field.
			$requestPath = $url;
		else
			$requestPath = $arrURL['path'] . ( isset($arrURL['query']) ? '?' . $arrURL['query'] : '' );

		if ( empty($requestPath) )
			$requestPath .= '/';

		$strHeaders = strtoupper($r['method']) . ' ' . $requestPath . ' HTTP/' . $r['httpversion'] . "\r\n";

		if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) )
			$strHeaders .= 'Host: ' . $arrURL['host'] . ':' . $arrURL['port'] . "\r\n";
		else
			$strHeaders .= 'Host: ' . $arrURL['host'] . "\r\n";

		if ( isset($r['user-agent']) )
			$strHeaders .= 'User-agent: ' . $r['user-agent'] . "\r\n";

		if ( is_array($r['headers']) ) {
			foreach ( (array) $r['headers'] as $header => $headerValue )
				$strHeaders .= $header . ': ' . $headerValue . "\r\n";
		} else {
			$strHeaders .= $r['headers'];
		}

		if ( $proxy->use_authentication() )
			$strHeaders .= $proxy->authentication_header() . "\r\n";

		$strHeaders .= "\r\n";

		if ( ! is_null($r['body']) )
			$strHeaders .= $r['body'];

		fwrite($handle, $strHeaders);

		if ( ! $r['blocking'] ) {
			stream_set_blocking( $handle, 0 );
			fclose( $handle );
			return array( 'headers' => array(), 'body' => '', 'response' => array('code' => false, 'message' => false), 'cookies' => array() );
		}

		$strResponse = '';
		$bodyStarted = false;
		$keep_reading = true;
		$block_size = 4096;
		if ( isset( $r['limit_response_size'] ) )
			$block_size = min( $block_size, $r['limit_response_size'] );

		// If streaming to a file setup the file handle
		if ( $r['stream'] ) {
			if ( ! WP_DEBUG )
				$stream_handle = @fopen( $r['filename'], 'w+' );
			else
				$stream_handle = fopen( $r['filename'], 'w+' );
			if ( ! $stream_handle )
				throw new Exception( "Could not open handle for fopen() to {$r['filename']}" );

			$bytes_written = 0;
			while ( ! feof($handle) && $keep_reading ) {
				$block = fread( $handle, $block_size );
				if ( ! $bodyStarted ) {
					$strResponse .= $block;
					if ( strpos( $strResponse, "\r\n\r\n" ) ) {
						$process = WP_Http::processResponse( $strResponse );
						$bodyStarted = true;
						$block = $process['body'];
						unset( $strResponse );
						$process['body'] = '';
					}
				}

				$this_block_size = strlen( $block );

				if ( isset( $r['limit_response_size'] ) && ( $bytes_written + $this_block_size ) > $r['limit_response_size'] )
					$block = substr( $block, 0, ( $r['limit_response_size'] - $bytes_written ) );

				$bytes_written_to_file = fwrite( $stream_handle, $block );

				if ( $bytes_written_to_file != $this_block_size ) {
					fclose( $handle );
					fclose( $stream_handle );
					throw new Exception( 'Failed to write request to temporary file.' );
				}

				$bytes_written += $bytes_written_to_file;

				$keep_reading = !isset( $r['limit_response_size'] ) || $bytes_written < $r['limit_response_size'];
			}

			fclose( $stream_handle );

		} else {
			$header_length = 0;
			while ( ! feof( $handle ) && $keep_reading ) {
				$block = fread( $handle, $block_size );
				$strResponse .= $block;
				if ( ! $bodyStarted && strpos( $strResponse, "\r\n\r\n" ) ) {
					$header_length = strpos( $strResponse, "\r\n\r\n" ) + 4;
					$bodyStarted = true;
				}
				$keep_reading = ( ! $bodyStarted || !isset( $r['limit_response_size'] ) || strlen( $strResponse ) < ( $header_length + $r['limit_response_size'] ) );
			}

			$process = WP_Http::processResponse( $strResponse );
			unset( $strResponse );

		}

		fclose( $handle );

		$arrHeaders = WP_Http::processHeaders( $process['headers'], $url );

		$response = array(
			'headers' => $arrHeaders['headers'],
			'body' => null, // Not yet processed
			'response' => $arrHeaders['response'],
			'cookies' => $arrHeaders['cookies'],
			'filename' => $r['filename']
		);

		// Handle redirects
		if ( false !== ( $redirect_response = WP_HTTP::handle_redirects( $url, $r, $response ) ) )
			return $redirect_response;

		// If the body was chunk encoded, then decode it.
		if ( ! empty( $process['body'] ) && isset( $arrHeaders['headers']['transfer-encoding'] ) && 'chunked' == $arrHeaders['headers']['transfer-encoding'] )
			$process['body'] = WP_Http::chunkTransferDecode($process['body']);

		if ( true === $r['decompress'] && true === WP_Http_Encoding::should_decode($arrHeaders['headers']) )
			$process['body'] = WP_Http_Encoding::decompress( $process['body'] );

		if ( isset( $r['limit_response_size'] ) && strlen( $process['body'] ) > $r['limit_response_size'] )
			$process['body'] = substr( $process['body'], 0, $r['limit_response_size'] );

		$response['body'] = $process['body'];

		return $response;
	}

	/**
	 * Verifies the received SSL certificate against it's Common Names and subjectAltName fields
	 *
	 * PHP's SSL verifications only verify that it's a valid Certificate, it doesn't verify if
	 * the certificate is valid for the hostname which was requested.
	 * This function verifies the requested hostname against certificate's subjectAltName field,
	 * if that is empty, or contains no DNS entries, a fallback to the Common Name field is used.
	 *
	 * IP Address support is included if the request is being made to an IP address.
	 *
	 * @static
	 *
	 * @param stream $stream The PHP Stream which the SSL request is being made over
	 * @param string $host The hostname being requested
	 * @return bool If the cerficiate presented in $stream is valid for $host
	 */
	static function verify_ssl_certificate( $stream, $host ) {
		$context_options = stream_context_get_options( $stream );

		if ( empty( $context_options['ssl']['peer_certificate'] ) )
			return false;

		$cert = openssl_x509_parse( $context_options['ssl']['peer_certificate'] );
		if ( ! $cert )
			return false;

		// If the request is being made to an IP address, we'll validate against IP fields in the cert (if they exist)
		$host_type = ( WP_HTTP::is_ip_address( $host ) ? 'ip' : 'dns' );

		$certificate_hostnames = array();
		if ( ! empty( $cert['extensions']['subjectAltName'] ) ) {
			$match_against = preg_split( '/,\s*/', $cert['extensions']['subjectAltName'] );
			foreach ( $match_against as $match ) {
				list( $match_type, $match_host ) = explode( ':', $match );
				if ( $host_type == strtolower( trim( $match_type ) ) ) // IP: or DNS:
					$certificate_hostnames[] = strtolower( trim( $match_host ) );
			}
		} elseif ( !empty( $cert['subject']['CN'] ) ) {
			// Only use the CN when the certificate includes no subjectAltName extension
			$certificate_hostnames[] = strtolower( $cert['subject']['CN'] );
		}

		// Exact hostname/IP matches
		if ( in_array( strtolower( $host ), $certificate_hostnames ) )
			return true;

		// IP's can't be wildcards, Stop processing
		if ( 'ip' == $host_type )
			return false;

		// Test to see if the domain is at least 2 deep for wildcard support
		if ( substr_count( $host, '.' ) < 2 )
			return false;

		// Wildcard subdomains certs (*.example.com) are valid for a.example.com but not a.b.example.com
		$wildcard_host = preg_replace( '/^[^.]+\./', '*.', $host );

		return in_array( strtolower( $wildcard_host ), $certificate_hostnames );
	}

	/**
	 * Whether this class can be used for retrieving an URL.
	 *
	 * @static
	 * @access public
	 *
	 * @return boolean False means this class can not be used, true means it can.
	 */
	public static function test( $args = array() ) {
		if ( ! function_exists( 'stream_socket_client' ) )
			return false;

		$is_ssl = isset( $args['ssl'] ) && $args['ssl'];

		if ( $is_ssl ) {
			if ( ! extension_loaded( 'openssl' ) )
				return false;
			if ( ! function_exists( 'openssl_x509_parse' ) )
				return false;
		}

		return true;
	}
}

/**
 * Deprecated HTTP Transport method which used fsockopen.
 *
 * This class is not used, and is included for backwards compatibility only.
 * All code should make use of WP_HTTP directly through it's API.
 *
 * @see WP_HTTP::request
 *
 * @deprecated 3.7.0 Please use WP_HTTP::request() directly
 */
class WP_HTTP_Fsockopen extends WP_HTTP_Streams {
	// For backwards compatibility for users who are using the class directly
}

/**
 * HTTP request method uses Curl extension to retrieve the url.
 *
 * Requires the Curl extension to be installed.
 */
class WP_Http_Curl {

	/**
	 * Temporary header storage for during requests.
	 *
	 * @access private
	 * @var string
	 */
	private $headers = '';

	/**
	 * Temporary body storage for during requests.
	 *
	 * @access private
	 * @var string
	 */
	private $body = '';

	/**
	 * The maximum amount of data to recieve from the remote server
	 *
	 * @access private
	 * @var int
	 */
	private $max_body_length = false;

	/**
	 * The file resource used for streaming to file.
	 *
	 * @access private
	 * @var resource
	 */
	private $stream_handle = false;

	/**
	 * Send a HTTP request to a URI using cURL extension.
	 *
	 * @access public
	 *
	 * @param string $url
	 * @param str|array $args Optional. Override the defaults.
	 * @return array 'headers', 'body', 'response', 'cookies' and 'filename' keys.
	 */
	function request($url, $args = array()) {
		$defaults = array(
			'method' => 'GET', 'timeout' => 5,
			'redirection' => 5, 'httpversion' => '1.0',
			'blocking' => true,
			'headers' => array(), 'body' => null, 'cookies' => array()
		);

		$r = array_merge( $defaults, $args );

		if ( isset($r['headers']['User-Agent']) ) {
			$r['user-agent'] = $r['headers']['User-Agent'];
			unset($r['headers']['User-Agent']);
		} else if ( isset($r['headers']['user-agent']) ) {
			$r['user-agent'] = $r['headers']['user-agent'];
			unset($r['headers']['user-agent']);
		}

		// Construct Cookie: header if any cookies are set.
		WP_Http::buildCookieHeader( $r );

		$handle = curl_init();

		// cURL offers really easy proxy support.
		$proxy = new WP_HTTP_Proxy();

		if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) ) {

			curl_setopt( $handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP );
			curl_setopt( $handle, CURLOPT_PROXY, $proxy->host() );
			curl_setopt( $handle, CURLOPT_PROXYPORT, $proxy->port() );

			if ( $proxy->use_authentication() ) {
				curl_setopt( $handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY );
				curl_setopt( $handle, CURLOPT_PROXYUSERPWD, $proxy->authentication() );
			}
		}

		$ssl_verify = isset($r['sslverify']) && $r['sslverify'];

		// CURLOPT_TIMEOUT and CURLOPT_CONNECTTIMEOUT expect integers. Have to use ceil since
		// a value of 0 will allow an unlimited timeout.
		$timeout = (int) ceil( $r['timeout'] );
		curl_setopt( $handle, CURLOPT_CONNECTTIMEOUT, $timeout );
		curl_setopt( $handle, CURLOPT_TIMEOUT, $timeout );

		curl_setopt( $handle, CURLOPT_URL, $url);
		curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $handle, CURLOPT_SSL_VERIFYHOST, ( $ssl_verify === true ) ? 2 : false );
		curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, $ssl_verify );
		curl_setopt( $handle, CURLOPT_CAINFO, $r['sslcertificates'] );
		curl_setopt( $handle, CURLOPT_USERAGENT, $r['user-agent'] );
		// The option doesn't work with safe mode or when open_basedir is set, and there's a
		// bug #17490 with redirected POST requests, so handle redirections outside Curl.
		curl_setopt( $handle, CURLOPT_FOLLOWLOCATION, false );
		if ( defined( 'CURLOPT_PROTOCOLS' ) ) // PHP 5.2.10 / cURL 7.19.4
			curl_setopt( $handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS );

		switch ( $r['method'] ) {
			case 'HEAD':
				curl_setopt( $handle, CURLOPT_NOBODY, true );
				break;
			case 'POST':
				curl_setopt( $handle, CURLOPT_POST, true );
				curl_setopt( $handle, CURLOPT_POSTFIELDS, $r['body'] );
				break;
			case 'PUT':
				curl_setopt( $handle, CURLOPT_CUSTOMREQUEST, 'PUT' );
				curl_setopt( $handle, CURLOPT_POSTFIELDS, $r['body'] );
				break;
			default:
				curl_setopt( $handle, CURLOPT_CUSTOMREQUEST, $r['method'] );
				if ( ! is_null( $r['body'] ) )
					curl_setopt( $handle, CURLOPT_POSTFIELDS, $r['body'] );
				break;
		}

		if ( true === $r['blocking'] ) {
			curl_setopt( $handle, CURLOPT_HEADERFUNCTION, array( $this, 'stream_headers' ) );
			curl_setopt( $handle, CURLOPT_WRITEFUNCTION, array( $this, 'stream_body' ) );
		}

		curl_setopt( $handle, CURLOPT_HEADER, false );

		if ( isset( $r['limit_response_size'] ) )
			$this->max_body_length = intval( $r['limit_response_size'] );
		else
			$this->max_body_length = false;

		// If streaming to a file open a file handle, and setup our curl streaming handler
		if ( $r['stream'] ) {
			if ( ! WP_DEBUG )
				$this->stream_handle = @fopen( $r['filename'], 'w+' );
			else
				$this->stream_handle = fopen( $r['filename'], 'w+' );
			if ( ! $this->stream_handle )
				throw new Exception( "Could not open handle for fopen() to {$r['filename']}" );
		} else {
			$this->stream_handle = false;
		}

		if ( !empty( $r['headers'] ) ) {
			// cURL expects full header strings in each element
			$headers = array();
			foreach ( $r['headers'] as $name => $value ) {
				$headers[] = "{$name}: $value";
			}
			curl_setopt( $handle, CURLOPT_HTTPHEADER, $headers );
		}

		if ( $r['httpversion'] == '1.0' )
			curl_setopt( $handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0 );
		else
			curl_setopt( $handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );

		// We don't need to return the body, so don't. Just execute request and return.
		if ( ! $r['blocking'] ) {
			curl_exec( $handle );

			if ( $curl_error = curl_error( $handle ) ) {
				curl_close( $handle );
				throw new Exception( $curl_error );
			}
			if ( in_array( curl_getinfo( $handle, CURLINFO_HTTP_CODE ), array( 301, 302 ) ) ) {
				curl_close( $handle );
				throw new Exception( 'Too many redirects.' );
			}

			curl_close( $handle );
			return array( 'headers' => array(), 'body' => '', 'response' => array('code' => false, 'message' => false), 'cookies' => array() );
		}

		$theResponse = curl_exec( $handle );
		$theHeaders = WP_Http::processHeaders( $this->headers, $url );
		$theBody = $this->body;

		$this->headers = '';
		$this->body = '';

		$curl_error = curl_errno( $handle );

		// If an error occured, or, no response
		if ( $curl_error || ( 0 == strlen( $theBody ) && empty( $theHeaders['headers'] ) ) ) {
			if ( CURLE_WRITE_ERROR /* 23 */ == $curl_error &&  $r['stream'] ) {
				fclose( $this->stream_handle );
				throw new Exception( 'Failed to write request to temporary file.' );
			}
			if ( $curl_error = curl_error( $handle ) ) {
				curl_close( $handle );
				throw new Exception( $curl_error );
			}
			if ( in_array( curl_getinfo( $handle, CURLINFO_HTTP_CODE ), array( 301, 302 ) ) ) {
				curl_close( $handle );
				throw new Exception( 'Too many redirects.' );
			}
		}

		$response = array();
		$response['code'] = curl_getinfo( $handle, CURLINFO_HTTP_CODE );
		$response['message'] = get_status_header_desc($response['code']);

		curl_close( $handle );

		if ( $r['stream'] )
			fclose( $this->stream_handle );

		$response = array(
			'headers'  => $theHeaders['headers'],
			'body'     => null,
			'response' => $response,
			'cookies'  => $theHeaders['cookies'],
			'filename' => $r['filename']
		);

		// Handle redirects
		if ( false !== ( $redirect_response = WP_HTTP::handle_redirects( $url, $r, $response ) ) )
			return $redirect_response;

		if ( true === $r['decompress'] && true === WP_Http_Encoding::should_decode($theHeaders['headers']) )
			$theBody = WP_Http_Encoding::decompress( $theBody );

		$response['body'] = $theBody;

		return $response;
	}

	/**
	 * Grab the headers of the cURL request
	 *
	 * Each header is sent individually to this callback, so we append to the $header property for temporary storage
	 *
	 * @access private
	 * @return int
	 */
	private function stream_headers( $handle, $headers ) {
		$this->headers .= $headers;
		return strlen( $headers );
	}

	/**
	 * Grab the body of the cURL request
	 *
	 * The contents of the document are passed in chunks, so we append to the $body property for temporary storage.
	 * Returning a length shorter than the length of $data passed in will cause cURL to abort the request as "completed"
	 *
	 * @access private
	 * @return int
	 */
	private function stream_body( $handle, $data ) {
		$data_length = strlen( $data );

		if ( $this->max_body_length && ( strlen( $this->body ) + $data_length ) > $this->max_body_length )
			$data = substr( $data, 0, ( $this->max_body_length - $data_length ) );

		if ( $this->stream_handle ) {
			$bytes_written = fwrite( $this->stream_handle, $data );
		} else {
			$this->body .= $data;
			$bytes_written = $data_length;
		}

		// Upon event of this function returning less than strlen( $data ) curl will error with CURLE_WRITE_ERROR
		return $bytes_written;
	}

	/**
	 * Whether this class can be used for retrieving an URL.
	 *
	 * @static
	 *
	 * @return boolean False means this class can not be used, true means it can.
	 */
	public static function test( $args = array() ) {
		if ( ! function_exists( 'curl_init' ) || ! function_exists( 'curl_exec' ) )
			return false;

		$is_ssl = isset( $args['ssl'] ) && $args['ssl'];

		if ( $is_ssl ) {
			$curl_version = curl_version();
			if ( ! (CURL_VERSION_SSL & $curl_version['features']) ) // Does this cURL version support SSL requests?
				return false;
		}

		return true;
	}
}

/**
 * Adds Proxy support to the HTTP API.
 *
 * There are caveats to proxy support. It requires that defines be made in the wp-config.php file to
 * enable proxy support. There are also a few filters that plugins can hook into for some of the
 * constants.
 *
 * Please note that only BASIC authentication is supported by most transports.
 * cURL MAY support more methods (such as NTLM authentication) depending on your environment.
 *
 * The constants are as follows:
 * <ol>
 * <li>WP_PROXY_HOST - Enable proxy support and host for connecting.</li>
 * <li>WP_PROXY_PORT - Proxy port for connection. No default, must be defined.</li>
 * <li>WP_PROXY_USERNAME - Proxy username, if it requires authentication.</li>
 * <li>WP_PROXY_PASSWORD - Proxy password, if it requires authentication.</li>
 * <li>WP_PROXY_BYPASS_HOSTS - Will prevent the hosts in this list from going through the proxy.
 * You do not need to have localhost and the blog host in this list, because they will not be passed
 * through the proxy. The list should be presented in a comma separated list, wildcards using * are supported, eg. *.foo.com</li>
 * </ol>
 *
 * An example can be as seen below.
 * <code>
 * define('WP_PROXY_HOST', '192.168.84.101');
 * define('WP_PROXY_PORT', '8080');
 * define('WP_PROXY_BYPASS_HOSTS', 'localhost, www.example.com, *.foo.com');
 * </code>
 */
class WP_HTTP_Proxy {

	/**
	 * Whether proxy connection should be used.
	 *
	 * @use WP_PROXY_HOST
	 * @use WP_PROXY_PORT
	 *
	 * @return bool
	 */
	function is_enabled() {
		return defined('WP_PROXY_HOST') && defined('WP_PROXY_PORT');
	}

	/**
	 * Whether authentication should be used.
	 *
	 * @use WP_PROXY_USERNAME
	 * @use WP_PROXY_PASSWORD
	 *
	 * @return bool
	 */
	function use_authentication() {
		return defined('WP_PROXY_USERNAME') && defined('WP_PROXY_PASSWORD');
	}

	/**
	 * Retrieve the host for the proxy server.
	 *
	 * @return string
	 */
	function host() {
		if ( defined('WP_PROXY_HOST') )
			return WP_PROXY_HOST;

		return '';
	}

	/**
	 * Retrieve the port for the proxy server.
	 *
	 * @return string
	 */
	function port() {
		if ( defined('WP_PROXY_PORT') )
			return WP_PROXY_PORT;

		return '';
	}

	/**
	 * Retrieve the username for proxy authentication.
	 *
	 * @return string
	 */
	function username() {
		if ( defined('WP_PROXY_USERNAME') )
			return WP_PROXY_USERNAME;

		return '';
	}

	/**
	 * Retrieve the password for proxy authentication.
	 *
	 * @return string
	 */
	function password() {
		if ( defined('WP_PROXY_PASSWORD') )
			return WP_PROXY_PASSWORD;

		return '';
	}

	/**
	 * Retrieve authentication string for proxy authentication.
	 *
	 * @return string
	 */
	function authentication() {
		return $this->username() . ':' . $this->password();
	}

	/**
	 * Retrieve header string for proxy authentication.
	 *
	 * @return string
	 */
	function authentication_header() {
		return 'Proxy-Authorization: Basic ' . base64_encode( $this->authentication() );
	}

	/**
	 * Whether URL should be sent through the proxy server.
	 *
	 * We want to keep localhost and the blog URL from being sent through the proxy server, because
	 * some proxies can not handle this. We also have the constant available for defining other
	 * hosts that won't be sent through the proxy.
	 *
	 * @uses WP_PROXY_BYPASS_HOSTS
	 *
	 * @param string $uri URI to check.
	 * @return bool True, to send through the proxy and false if, the proxy should not be used.
	 */
	function send_through_proxy( $uri ) {
		// parse_url() only handles http, https type URLs, and will emit E_WARNING on failure.
		// This will be displayed on blogs, which is not reasonable.
		$check = @parse_url($uri);

		// Malformed URL, can not process, but this could mean ssl, so let through anyway.
		if ( $check === false )
			return true;

		if ( $check['host'] == 'localhost' || $check['host'] == $_SERVER['SERVER_NAME'] )
			return false;

		if ( !defined('WP_PROXY_BYPASS_HOSTS') )
			return true;

		static $bypass_hosts;
		static $wildcard_regex = false;
		if ( null == $bypass_hosts ) {
			$bypass_hosts = preg_split('|,\s*|', WP_PROXY_BYPASS_HOSTS);

			if ( false !== strpos(WP_PROXY_BYPASS_HOSTS, '*') ) {
				$wildcard_regex = array();
				foreach ( $bypass_hosts as $host )
					$wildcard_regex[] = str_replace( '\*', '.+', preg_quote( $host, '/' ) );
				$wildcard_regex = '/^(' . implode('|', $wildcard_regex) . ')$/i';
			}
		}

		if ( !empty($wildcard_regex) )
			return !preg_match($wildcard_regex, $check['host']);
		else
			return !in_array( $check['host'], $bypass_hosts );
	}
}
/**
 * Internal representation of a single cookie.
 *
 * Returned cookies are represented using this class, and when cookies are set, if they are not
 * already a WP_Http_Cookie() object, then they are turned into one.
 */
class WP_Http_Cookie {

	/**
	 * Cookie name.
	 *
	 * @var string
	 */
	var $name;

	/**
	 * Cookie value.
	 *
	 * @var string
	 */
	var $value;

	/**
	 * When the cookie expires.
	 *
	 * @var string
	 */
	var $expires;

	/**
	 * Cookie URL path.
	 *
	 * @var string
	 */
	var $path;

	/**
	 * Cookie Domain.
	 *
	 * @var string
	 */
	var $domain;

	/**
	 * Sets up this cookie object.
	 *
	 * The parameter $data should be either an associative array containing the indices names below
	 * or a header string detailing it.
	 *
	 * If it's an array, it should include the following elements:
	 * <ol>
	 * <li>Name</li>
	 * <li>Value - should NOT be urlencoded already.</li>
	 * <li>Expires - (optional) String or int (UNIX timestamp).</li>
	 * <li>Path (optional)</li>
	 * <li>Domain (optional)</li>
	 * <li>Port (optional)</li>
	 * </ol>
	 *
	 * @access public
	 *
	 * @param string|array $data Raw cookie data.
	 * @param string $requested_url The URL which the cookie was set on, used for default 'domain' and 'port' values
	 */
	function __construct( $data, $requested_url = '' ) {
		if ( $requested_url )
			$arrURL = @parse_url( $requested_url );
		if ( isset( $arrURL['host'] ) )
			$this->domain = $arrURL['host'];
		$this->path = isset( $arrURL['path'] ) ? $arrURL['path'] : '/';
		if (  '/' != substr( $this->path, -1 ) )
			$this->path = dirname( $this->path ) . '/';

		if ( is_string( $data ) ) {
			// Assume it's a header string direct from a previous request
			$pairs = explode( ';', $data );

			// Special handling for first pair; name=value. Also be careful of "=" in value
			$name  = trim( substr( $pairs[0], 0, strpos( $pairs[0], '=' ) ) );
			$value = substr( $pairs[0], strpos( $pairs[0], '=' ) + 1 );
			$this->name  = $name;
			$this->value = urldecode( $value );
			array_shift( $pairs ); //Removes name=value from items.

			// Set everything else as a property
			foreach ( $pairs as $pair ) {
				$pair = rtrim($pair);
				if ( empty($pair) ) //Handles the cookie ending in ; which results in a empty final pair
					continue;

				list( $key, $val ) = strpos( $pair, '=' ) ? explode( '=', $pair ) : array( $pair, '' );
				$key = strtolower( trim( $key ) );
				if ( 'expires' == $key )
					$val = strtotime( $val );
				$this->$key = $val;
			}
		} else {
			if ( !isset( $data['name'] ) )
				return false;

			// Set properties based directly on parameters
			foreach ( array( 'name', 'value', 'path', 'domain', 'port' ) as $field ) {
				if ( isset( $data[ $field ] ) )
					$this->$field = $data[ $field ];
			}

			if ( isset( $data['expires'] ) )
				$this->expires = is_int( $data['expires'] ) ? $data['expires'] : strtotime( $data['expires'] );
			else
				$this->expires = null;
		}
	}

	/**
	 * Confirms that it's OK to send this cookie to the URL checked against.
	 *
	 * Decision is based on RFC 2109/2965, so look there for details on validity.
	 *
	 * @access public
	 *
	 * @param string $url URL you intend to send this cookie to
	 * @return boolean true if allowed, false otherwise.
	 */
	function test( $url ) {
		if ( is_null( $this->name ) )
			return false;

		// Expires - if expired then nothing else matters
		if ( isset( $this->expires ) && time() > $this->expires )
			return false;

		// Get details on the URL we're thinking about sending to
		$url = parse_url( $url );
		$url['port'] = isset( $url['port'] ) ? $url['port'] : ( 'https' == $url['scheme'] ? 443 : 80 );
		$url['path'] = isset( $url['path'] ) ? $url['path'] : '/';

		// Values to use for comparison against the URL
		$path   = isset( $this->path )   ? $this->path   : '/';
		$port   = isset( $this->port )   ? $this->port   : null;
		$domain = isset( $this->domain ) ? strtolower( $this->domain ) : strtolower( $url['host'] );
		if ( false === stripos( $domain, '.' ) )
			$domain .= '.local';

		// Host - very basic check that the request URL ends with the domain restriction (minus leading dot)
		$domain = substr( $domain, 0, 1 ) == '.' ? substr( $domain, 1 ) : $domain;
		if ( substr( $url['host'], -strlen( $domain ) ) != $domain )
			return false;

		// Port - supports "port-lists" in the format: "80,8000,8080"
		if ( !empty( $port ) && !in_array( $url['port'], explode( ',', $port) ) )
			return false;

		// Path - request path must start with path restriction
		if ( substr( $url['path'], 0, strlen( $path ) ) != $path )
			return false;

		return true;
	}

	/**
	 * Convert cookie name and value back to header string.
	 *
	 * @access public
	 *
	 * @return string Header encoded cookie name and value.
	 */
	function getHeaderValue() {
		if ( ! isset( $this->name ) || ! isset( $this->value ) )
			return '';

		return $this->name . '=' . $this->value;
	}

	/**
	 * Retrieve cookie header for usage in the rest of the HTTP API.
	 *
	 * @access public
	 *
	 * @return string
	 */
	function getFullHeader() {
		return 'Cookie: ' . $this->getHeaderValue();
	}
}

/**
 * Implementation for deflate and gzip transfer encodings.
 *
 * Includes RFC 1950, RFC 1951, and RFC 1952.
 */
class WP_Http_Encoding {

	/**
	 * Compress raw string using the deflate format.
	 *
	 * Supports the RFC 1951 standard.
	 *
	 * @param string $raw String to compress.
	 * @param int $level Optional, default is 9. Compression level, 9 is highest.
	 * @param string $supports Optional, not used. When implemented it will choose the right compression based on what the server supports.
	 * @return string|bool False on failure.
	 */
	public static function compress( $raw, $level = 9, $supports = null ) {
		return gzdeflate( $raw, $level );
	}

	/**
	 * Decompression of deflated string.
	 *
	 * Will attempt to decompress using the RFC 1950 standard, and if that fails
	 * then the RFC 1951 standard deflate will be attempted. Finally, the RFC
	 * 1952 standard gzip decode will be attempted. If all fail, then the
	 * original compressed string will be returned.
	 *
	 * @param string $compressed String to decompress.
	 * @param int $length The optional length of the compressed data.
	 * @return string|bool False on failure.
	 */
	public static function decompress( $compressed, $length = null ) {

		if ( empty($compressed) )
			return $compressed;

		if ( false !== ( $decompressed = @gzinflate( $compressed ) ) )
			return $decompressed;

		if ( false !== ( $decompressed = WP_Http_Encoding::compatible_gzinflate( $compressed ) ) )
			return $decompressed;

		if ( false !== ( $decompressed = @gzuncompress( $compressed ) ) )
			return $decompressed;

		if ( function_exists('gzdecode') ) {
			$decompressed = @gzdecode( $compressed );

			if ( false !== $decompressed )
				return $decompressed;
		}

		return $compressed;
	}

	/**
	 * Decompression of deflated string while staying compatible with the majority of servers.
	 *
	 * Certain Servers will return deflated data with headers which PHP's gzinflate()
	 * function cannot handle out of the box. The following function has been created from
	 * various snippets on the gzinflate() PHP documentation.
	 *
	 * Warning: Magic numbers within. Due to the potential different formats that the compressed
	 * data may be returned in, some "magic offsets" are needed to ensure proper decompression
	 * takes place.
	 *
	 * @link http://au2.php.net/manual/en/function.gzinflate.php#70875
	 * @link http://au2.php.net/manual/en/function.gzinflate.php#77336
	 *
	 * @param string $gzData String to decompress.
	 * @return string|bool False on failure.
	 */
	public static function compatible_gzinflate($gzData) {

		// Compressed data might contain a full header, if so strip it for gzinflate()
		if ( substr($gzData, 0, 3) == "\x1f\x8b\x08" ) {
			$i = 10;
			$flg = ord( substr($gzData, 3, 1) );
			if ( $flg > 0 ) {
				if ( $flg & 4 ) {
					list($xlen) = unpack('v', substr($gzData, $i, 2) );
					$i = $i + 2 + $xlen;
				}
				if ( $flg & 8 )
					$i = strpos($gzData, "\0", $i) + 1;
				if ( $flg & 16 )
					$i = strpos($gzData, "\0", $i) + 1;
				if ( $flg & 2 )
					$i = $i + 2;
			}
			$decompressed = @gzinflate( substr($gzData, $i, -8) );
			if ( false !== $decompressed )
				return $decompressed;
		}

		// Compressed data from java.util.zip.Deflater amongst others.
		$decompressed = @gzinflate( substr($gzData, 2) );
		if ( false !== $decompressed )
			return $decompressed;

		return false;
	}

	/**
	 * What encoding types to accept and their priority values.
	 *
	 * @return string Types of encoding to accept.
	 */
	public static function accept_encoding( $url, $args ) {
		$type = array();
		$compression_enabled = WP_Http_Encoding::is_available();

		if ( ! $args['decompress'] ) // decompression specifically disabled
			$compression_enabled = false;
		elseif ( $args['stream'] ) // disable when streaming to file
			$compression_enabled = false;
		elseif ( isset( $args['limit_response_size'] ) ) // If only partial content is being requested, we won't be able to decompress it
			$compression_enabled = false;

		if ( $compression_enabled ) {
			if ( function_exists( 'gzinflate' ) )
				$type[] = 'deflate;q=1.0';

			if ( function_exists( 'gzuncompress' ) )
				$type[] = 'compress;q=0.5';

			if ( function_exists( 'gzdecode' ) )
				$type[] = 'gzip;q=0.5';
		}

		return implode(', ', $type);
	}

	/**
	 * What encoding the content used when it was compressed to send in the headers.
	 *
	 * @return string Content-Encoding string to send in the header.
	 */
	public static function content_encoding() {
		return 'deflate';
	}

	/**
	 * Whether the content be decoded based on the headers.
	 *
	 * @param array|string $headers All of the available headers.
	 * @return bool
	 */
	public static function should_decode($headers) {
		if ( is_array( $headers ) ) {
			if ( array_key_exists('content-encoding', $headers) && ! empty( $headers['content-encoding'] ) )
				return true;
		} else if ( is_string( $headers ) ) {
			return ( stripos($headers, 'content-encoding:') !== false );
		}

		return false;
	}

	/**
	 * Whether decompression and compression are supported by the PHP version.
	 *
	 * Each function is tested instead of checking for the zlib extension, to
	 * ensure that the functions all exist in the PHP version and aren't
	 * disabled.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return ( function_exists('gzuncompress') || function_exists('gzdeflate') || function_exists('gzinflate') );
	}
}
