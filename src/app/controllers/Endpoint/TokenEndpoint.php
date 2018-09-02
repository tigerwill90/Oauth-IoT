<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
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

    /** @var Memcached  */
    private $mc;

    public function __construct(JoseHelperInterface $joseHelper, Memcached $mc, LoggerInterface $logger = null)
    {
        $this->joseHelper = $joseHelper;
        $this->mc = $mc;
        $this->logger = $logger;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws \Exception
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $payload = [
            'exp' => time() + 60,
            'jti' => '01234',
            'aud' => 'iot_a'
        ];

        /**
         * kid =>
         *
         */

        $jwkSet = $this->mc->get('symmetricKey');
        $fromCache = false;
        if ($jwkSet) {
            $fromCache = true;
            $jwkSet = JWKSet::createFromJson($jwkSet);
        } else {
            $jwk = JWK::create([
                'kty' => 'oct',
                'k' => getenv('KEY'),
                'alg' => 'HS256',
                'use' => 'sig',
                'enc' => 'A256CBC-HS512',
                'kid' => '12345'
            ]);
            $jwkSet = JWKSet::createFromKeys([]);
            $jwkSet = $jwkSet->with($jwk);
            $this->mc->set('symmetricKey', json_encode($jwkSet), 30);
        }

        try {
            $token = $this->joseHelper
                ->setJwk($jwkSet->get('12345'))
                ->createToken($payload);
        } catch (\Exception $e) {
            throw new \LogicException($e->getMessage());
        }

       try {
           $foo = $this->joseHelper->getHeaders();
       } catch (\Exception $e) {
            throw $e;
       }

        $body = $response->getBody();
        $body->write(json_encode(['access_token' => $token, 'headers' => $foo, 'from_cache' => $fromCache]));
        return $response->withBody($body)->withHeader('Content-Type', 'application/json');
    }

    /**
     * @param string $message
     * @param array $context
     * @return TokenEndpoint
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}