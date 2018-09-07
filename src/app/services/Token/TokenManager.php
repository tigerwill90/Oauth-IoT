<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 07.09.2018
 * Time: 12:03
 */

namespace Oauth\Services\Token;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Memcached;
use Oauth\Services\Helpers\JoseHelperInterface;
use Oauth\Services\Resources\ResourceInterface;
use Psr\Log\LoggerInterface;
use RandomLib\Generator;

class TokenManager
{
    private const TOKEN_CHAR_GEN = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** @var Memcached  */
    private $mc;

    /** @var LoggerInterface  */
    private $logger;

    /** @var Generator  */
    private $generator;

    /** @var JoseHelperInterface  */
    private $joseHelper;

    /** @var JWKSet */
    private $jwkSet;

    /** @var JWK */
    private $sharedJwk;

    /** @var JWK */
    private $accessTokenJwk;

    /** @var string */
    private $accessToken;

    public function __construct(Memcached $mc, Generator $generator, JoseHelperInterface $joseHelper, LoggerInterface $logger = null)
    {
        $this->mc = $mc;
        $this->generator = $generator;
        $this->joseHelper = $joseHelper;
        $this->logger = $logger;
    }

    /**
     * @param ResourceInterface $resource
     * @return TokenManager
     * @throws \Exception
     */
    public function createKeySet(ResourceInterface $resource) : self
    {
        //$popMethod = $resource->getPopMethod();

        // temporary process for light_introspection method

        $kid = $this->generator->generateString(4, self::TOKEN_CHAR_GEN);

        // create KEYSet
        $this->sharedJwk = JWK::create([
            'alg' => 'AES128-ECB',
            'kty' => 'oct',
            'kid' => $kid . '-s',
            'k' => $this->generator->generateString(16, self::TOKEN_CHAR_GEN),
            'key_ops' => ['encrypt', 'decrypt']
        ]);

        $this->accessTokenJwk = JWK::create([
            'alg' => 'HS256',
            'kty' => 'oct',
            'use' => 'sig',
            'k' => $this->generator->generateString(32, self::TOKEN_CHAR_GEN),
            'kid' => $kid,
        ]);

        $this->jwkSet = JWKSet::createFromKeys([$this->sharedJwk, $this->accessTokenJwk]);

        $this->mc->set($resource->getAudience(), $this->jwkSet, 1000);

        $this->accessToken = $this->joseHelper
                ->setJwk($this->accessTokenJwk)
                ->createToken([
                    'jti' => $this->generator->generateString(8, self::TOKEN_CHAR_GEN),
                    'aud' => $resource->getAudience(),
                    'exp' => time() + 1000
                ]);

        return $this;
    }

    public function getSharedKey() : string
    {
        return $this->sharedJwk->get('k');
    }

    public function getAccessToken() : string
    {
        return $this->accessToken;
    }

    /**
     * @param string $message
     * @param array $context
     * @return TokenManager
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }

}
