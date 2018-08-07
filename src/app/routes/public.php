<?php

    use \Psr\Http\Message\ServerRequestInterface;
    use \Psr\Http\Message\ResponseInterface;
    use phpseclib\Crypt\AES;

    const SHAREDKEY = 'AaBbCcDdEe0123Az';

    $app->get('/', function (ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {
        $body = $response->getBody();
        $body->write(json_encode(['status' => 'work in progress']));
        return $response->withBody($body);
    });

    /**
     * Post route provide
     */
    $app->map(['GET', 'POST'],'/keys', function(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {

      $headers = $request->getHeader('HTTP_AUTHORIZATION');
      error_log('headers : ' . json_encode($request->getHeaders()));
      $bearer = '';
      if (isset($headers[0])) {
          if (preg_match('/Bearer\s+(.*)$/i', $headers[0],$matches)) {
              $bearer =  $matches[1];
          }
          else {
              return $response->withStatus(401);
          }
      } else {
          $args = $request->getParsedBody();
          if (isset($args['Bearer'])) {
              $bearer = $args['Bearer'];
          } else {
              return $response->withStatus(401);
          }
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

      if ($bearer === 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') {
          $body = $response->getBody();
          $body->write(json_encode(['key' => base64_encode($cipher->encrypt($plaintext))], JSON_UNESCAPED_SLASHES));
          return $response->withBody($body)->withHeader('content-type', 'application/json');
      }

      return $response->withStatus(401);
    });

    $app->get('/weather', function(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {
        $curl = curl_init('http://192.168.192.80/protected');
        $authorization = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json' , $authorization));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, "HandleHeaderLine");
        curl_setopt($curl, CURLOPT_TIMEOUT,10);
        $payload = curl_exec($curl);

        // encoded message
        $encoded = json_decode($payload, true)['encoded'];
        // decode message
        $encrypted = base64_decode($encoded);

        // AES set up
        $cipher = new AES(AES::MODE_ECB);
        $cipher->setKey(SHAREDKEY);
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
