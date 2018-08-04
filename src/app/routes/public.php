<?php

  use \Psr\Http\Message\ServerRequestInterface;
  use \Psr\Http\Message\ResponseInterface;

  $app->post('/keys', function(ServerRequestInterface $request, ResponseInterface $response) {
      $args = $request->getParsedBody();
      //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\\r
      //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
      $bearer = substr($args['Bearer'], 0, -1);
      error_log($bearer);
      if ($bearer === 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') {
          return $response->getBody()->write(json_encode(['key' => 'DZqq88ynCDS51jRahqz2/wAAAAAAAABH'], JSON_UNESCAPED_SLASHES));
      }
      return $response->withStatus(401);
  });
