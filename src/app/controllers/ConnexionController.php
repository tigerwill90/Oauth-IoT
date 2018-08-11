<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;


use Oauth\Services\Jose\Jose;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ConnexionController
{

    private $joseService;

    public function __construct(Jose $joseService)
    {
        $this->joseService = $joseService;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response)
    {

        $payload = [
            'iat' => time() + 60,
            'nbf' => time(),
            'exp' => time() + 1000,
            'iss' => 'My service',
            'aud' => 'Your application',
        ];

        $token = $this->joseService
            ->createKey('secret')
            ->createAlgorithmManager(['HS256'])
            ->createJwsObject($payload, ['alg' => 'HS256'])
            ->serializeToken()
            ->getToken();

        $body = $response->getBody();
        $body->write(json_encode(['foo' => $token]));
        return $response->withBody($body);
    }
}