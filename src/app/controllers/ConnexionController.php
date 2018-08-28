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
            'exp' => time() + 10000,
            'jti' => '0123456789'
        ];

        $token = $this->joseService
            ->createKey(getenv('KEY'), 'oct')
            ->createAlgorithmManager(['HS256'])
            ->createJwsObject($payload, ['alg' => 'HS256', 'typ' => 'JWT'])
            ->serializeToken()
            ->getToken();

        $body = $response->getBody();
        $body->write(json_encode(['access_token' => $token]));
        return $response->withBody($body);
    }
}