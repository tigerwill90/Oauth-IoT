<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Jose\JoseInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class ConnexionController
{
    /** @var JoseInterface  */
    private $joseService;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(JoseInterface $joseService, LoggerInterface $logger)
    {
        $this->joseService = $joseService;
        $this->logger = $logger;
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
            ->createKey(getenv('KEY'), 'oct')
            ->createAlgorithmManager(['HS384'])
            ->createJwsObject($payload, ['alg' => 'HS384', 'typ' => 'JWT'])
            ->serializeToken()
            ->getToken();

        $body = $response->getBody();
        $body->write(json_encode(['foo' => $token]));
        return $response->withBody($body);
    }
}