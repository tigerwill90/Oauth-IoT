<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Helpers\JoseHelperInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class ConnexionController
{
    /** @var JoseHelperInterface  */
    private $joseHelper;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(JoseHelperInterface $joseHelper, LoggerInterface $logger)
    {
        $this->joseHelper = $joseHelper;
        $this->logger = $logger;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response)
    {
        $payload = [
            'exp' => time() + 1000,
            'jti' => '0123456789'
        ];

        try {
            $token = $this->joseHelper
                ->setJwkKey(getenv('KEY'), 'oct')
                ->setJoseType('JWE')
                ->setJoseAlgorithm('A128KW', 'A256CBC-HS512')
                ->createJoseToken($payload);
        } catch (\Exception $e) {
            throw new \LogicException($e->getMessage());
        }

        //$this->joseHelper->setJoseToken('eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MzU0OTA0NDgsImp0aSI6IjAxMjM0NTY3ODkifQ.wMV3d_fVfwIBbtCMoNNZhB_fzngesXvY1mwrGn3hHlbCHc8HrFqf1bn7z2Z123y7');

        $foo = $this->joseHelper->getHeaders();

        $body = $response->getBody();
        $body->write(json_encode(['access_token' => $token, 'headers' => $foo]));
        return $response->withBody($body)->withHeader('Content-Type', 'application/json');
    }
}