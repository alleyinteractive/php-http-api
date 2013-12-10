## Synopsis

A standalone HTTP API extrapolated from WordPress. This is for developers who appreciate the simplicity of that API and want to use it outside their WordPress projects.

## Code Example

```
<?php
# Load the HTTP API Library
require_once( 'http_api/functions.php' );

# Post to some endpoint
$response = remote_post( 'http://localhost/endpoint.php', array( 'body' => json_encode( $query ) ) );

# Parse the response as JSON
$body = json_decode( remote_retrieve_body( $response ) );
?>
```

## Installation

Drop this library in your project and require it!

## API Reference

Check out the [WordPress HTTP API](http://codex.wordpress.org/HTTP_API) for a full reference. You can do almost everything in that API by simply removing the "wp_" namespace.

## License

Copyright 2013 Alley Interactive

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

This program incorporates work covered by the following copyright and
permission notices:

  WordPress - Web publishing software

  Copyright 2003-2010 by the contributors

  WordPress is released under the GPL
