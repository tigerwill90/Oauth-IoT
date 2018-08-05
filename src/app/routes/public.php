<?php

  use \Psr\Http\Message\ServerRequestInterface;
  use \Psr\Http\Message\ResponseInterface;
  use phpseclib\Crypt\AES;


  $app->post('/keys', function(ServerRequestInterface $request, ResponseInterface $response) {
      $args = $request->getParsedBody();
      $cipher = new AES(AES::MODE_ECB); //encryption single
      $cipher->setKey('ABCDEFGHIJ012345');
      $cipher->disablePadding();
      $plaintext = '012345ABCDEFGHIJ';
      error_log('Encrypted : ' . $cipher->encrypt($plaintext));
      error_log('Encoded : ' . (base64_encode($cipher->encrypt($plaintext))));

      $bearer = substr($args['Bearer'], 0, -1);
      if ($bearer === 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') {
          return $response->getBody()->write(json_encode(['key' => base64_encode($cipher->encrypt($plaintext))], JSON_UNESCAPED_SLASHES));
      }
      return $response->withStatus(401);
  });
