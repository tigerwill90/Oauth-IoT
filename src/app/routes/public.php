<?php

    use \Psr\Http\Message\ServerRequestInterface;
    use \Psr\Http\Message\ResponseInterface;
    use phpseclib\Crypt\AES;

    const SHAREDKEY = 'XOhk2bpZ2C9Vycof';

    $app->get('/', function (ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {
        $body = $response->getBody();
        $body->write(json_encode(['status' => 'work in progress']));
        return $response->withBody($body);
    });

    $app->map(['GET','POST'],'/introspect', Oauth\Controllers\IntrospectionEndpoint::class);
    $app->map(['GET', 'POST'],'/token', Oauth\Controllers\TokenEndpoint::class);
    $app->group('/auth', function () {
        $this->get('', \Oauth\Controllers\AuthorizationEndpoint::class . ':sign');
        $this->post('', \Oauth\Controllers\AuthorizationEndpoint::class . ':login')->setName('auth');
    });
    $app->group('/clients', function() {
        $this->post('', \Oauth\Controllers\CreateClientController::class);
        $this->delete('/{clientId}', \Oauth\Controllers\DeleteClientController::class);
        $this->map(['PUT', 'PATCH'],'/{clientId}', \Oauth\Controllers\UpdateClientController::class);
    });

    /**
     * Post route provide
     */
    $app->post('/keys', function(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {

      // HTTP AuthorizationManager
      $headers = $request->getHeader('HTTP_AUTHORIZATION');
      error_log('headers : ' . print_r($request->getHeaders(), true));
      if (isset($headers[0])) {
          if (preg_match('/Basic\s+(.*)$/i', $headers[0],$matches)) {
              $client =  $matches[1];
              error_log('client : ' . base64_decode($client));
          }
          else {
              return $response->withStatus(401);
          }
      }

      // Fetch access token from token introspection
      $args = $request->getParsedBody();
      error_log('body : ' . print_r($request->getParsedBody(), true));
      if (isset($args['access_token'])) {
          $bearer =  $args['access_token'];
      } else {
          return $response->withStatus(401);
      }

      $cipher = new AES(AES::MODE_ECB); //encryption single
      //$cipher = new AES();

      $cipher->setKey('abcdef!hij012345');

      //$cipher->setIV('0123456789012345');
      $cipher->disablePadding();
      //$plaintext = bin2hex(random_bytes(8));
      $plaintext = SHAREDKEY;
      //error_log('Encrypted : ' . $cipher->encrypt($plaintext));
      //error_log('Encoded : ' . (base64_encode($cipher->encrypt($plaintext))));
      error_log('Bearer : ' . $bearer);

      if ($bearer === 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwcjVlNiIsImV4cCI6MTU2NTI2Njc3OH0.OZhc-IXCG4PxcyhVhaWXkwTkL_NaxM489mynfbkPgh') {
          $body = $response->getBody();
          $body->write(json_encode(['active' => true, 'key' => base64_encode($cipher->encrypt($plaintext))], JSON_UNESCAPED_SLASHES));
          return $response->withBody($body)->withHeader('content-type', 'application/json');
      }

      return $response->withStatus(401);
    });

    $app->get('/wind', function(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {

        $curl = curl_init('http://192.168.192.51/wind/direction');
        $authorization = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjhaMkgifQ.eyJleHAiOjE1Mzg0ODE3OTQsImF1ZCI6ImlvdF8yIiwianRpIjoiYTJYdEdoZ202cSIsInNjb3BlIjoiUmd5cm8gUmFuZW5vIn0.hSFMM_viRHKtSrlYep381E1ijqsltMC6MJbaZbKDkj4';
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json' , $authorization));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, 'HandleHeaderLine');
        curl_setopt($curl, CURLOPT_TIMEOUT,10);
        $payload = curl_exec($curl);

        // encoded message
        $data = json_decode($payload, true);
        $encoded = $data['encoded'];
        $length = $data['length'];

        // decode message
        $encrypted = base64_decode($encoded);

        // AES set up
        $cipher = new AES(AES::MODE_CBC);
        $cipher->setKeyLength(256);
        $cipher->setKey('dYi04WLPKv1kFcSbmz8TJ74OMt95pKMX');
        $cipher->disablePadding();

        // Decrypt
        $message = $cipher->decrypt($encrypted);

        $message = substr($message, 0, $length);
        $message = substr($message, 16);

        curl_close($curl);
        $body = $response->getBody();
        $body->write(json_encode(['message' => $message], JSON_UNESCAPED_SLASHES));
        return $response->withBody($body);
    });

$app->get('/move', function(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {

    $curl = curl_init('http://192.168.192.80/move');
    $authorization = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZOUmcifQ.eyJleHAiOjE1Mzg0Njg1OTcsImF1ZCI6ImlvdF8yIiwianRpIjoibnRPM2RSTThQaCIsInNjb3BlIjoiUmd5cm8gUmFuZW5vIn0.rdKp6XtUCrUZI2W_ms9da25I3W6q80gzoha6HjCJLs0';
    curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json' , $authorization));
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HEADERFUNCTION, 'HandleHeaderLine');
    curl_setopt($curl, CURLOPT_TIMEOUT,10);
    $payload = curl_exec($curl);

    // encoded message
    $data = json_decode($payload, true);
    $encoded = $data['encoded'];
    $length = $data['length'];

    // decode message
    $encrypted = base64_decode($encoded);

    // AES set up
    $cipher = new AES(AES::MODE_ECB);
    $cipher->setKeyLength(128);
    $cipher->setKey('JVa3yxZUMvj3VaNIq0UGkpKb2jzWw3jk');
    $cipher->disablePadding();

    // Decrypt
    $message = $cipher->decrypt($encrypted);

    curl_close($curl);
    $body = $response->getBody();
    $body->write(json_encode(['message' => $message], JSON_UNESCAPED_SLASHES));
    return $response->withBody($body);
});

    function HandleHeaderLine($curl, $header_line) : int {
        //echo "<br>YEAH: ".$header_line; // or do whatever
        return strlen($header_line);
    }
