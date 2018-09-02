<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;

use Jose\Component\Core\JWK;
use Oauth\Services\Helpers\JoseHelperInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Memcached;

final class TokenEndpoint
{
    /** @var JoseHelperInterface  */
    private $joseHelper;

    /** @var LoggerInterface  */
    private $logger;

    private $mc;

    public function __construct(JoseHelperInterface $joseHelper, Memcached $mc, LoggerInterface $logger)
    {
        $this->joseHelper = $joseHelper;
        $this->mc = $mc;
        $this->logger = $logger;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $payload = [
            'exp' => time() + 20,
            'jti' => '0123456789'
        ];

        $jsonJwk = $this->mc->get('jwk');
        $fromCache = false;
        if ($jsonJwk) {
            $fromCache = true;
            $jwk = JWK::createFromJson($jsonJwk);
        } else {
            $jwk = JWK::create([
                'kty' => 'oct',
                'k' => getenv('KEY')
            ]);
            $this->mc->set('jwk', json_encode($jwk), 30);
        }

        try {
            $token = $this->joseHelper
                ->setJwk($jwk)
                ->setType('JWT')
                ->setAlgorithm('HS256')
                ->createToken($payload);
        } catch (\Exception $e) {
            throw new \LogicException($e->getMessage());
        }

        //$this->joseHelper->setJoseToken('eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MzU0OTA0NDgsImp0aSI6IjAxMjM0NTY3ODkifQ.wMV3d_fVfwIBbtCMoNNZhB_fzngesXvY1mwrGn3hHlbCHc8HrFqf1bn7z2Z123y7');

       try {
           $foo = $this->joseHelper->getHeaders();
       } catch (\Exception $e) {
            throw $e;
       }

        $body = $response->getBody();
        $body->write(json_encode(['access_token' => $token, 'headers' => $foo, 'from_cache' => $fromCache]));
        return $response->withBody($body)->withHeader('Content-Type', 'application/json');
    }
}