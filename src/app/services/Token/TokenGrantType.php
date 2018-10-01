<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 12:58
 */

namespace Oauth\Services\Token;

use Oauth\Services\AudienceInterface;
use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Helpers\JoseHelperInterface;
use Oauth\Services\IntrospectionInterface;
use Memcached;
use Oauth\Services\Resources\ResourceInterface;
use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\ResourceStorageInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use RandomLib\Generator;

abstract class TokenGrantType
{
    // Alphanumeric characters
    protected const TOKEN_CHAR_GEN = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** @var IntrospectionInterface  */
    protected $introspection;

    /** @var ClientStorageInterface */
    protected $clientStorage;

    /** @var array */
    protected $errors;

    /** @var ClientInterface|AudienceInterface */
    protected $client;

    /** @var LoggerInterface  */
    protected $logger;

    /** @var array */
    protected $claims;

    /** @var ResourceInterface */
    protected $resource;

    /** @var Generator  */
    protected $generator;

    /** @var JoseHelperInterface  */
    protected $joseHelper;

    /** @var ResourceStorageInterface  */
    protected $resourceStorage;

    /** @var Memcached  */
    protected $mc;

    public function __construct(IntrospectionInterface $introspection, ClientStorageInterface $clientStorage, ResourceStorageInterface $resourceStorage, Memcached $mc, Generator $generator, JoseHelperInterface $joseHelper, LoggerInterface $logger = null)
    {
        $this->introspection = $introspection;
        $this->clientStorage = $clientStorage;
        $this->generator = $generator;
        $this->joseHelper = $joseHelper;
        $this->resourceStorage = $resourceStorage;
        $this->mc = $mc;
        $this->logger = $logger;
    }

    /**
     * @param string $credentials
     * @throws InvalidClientCredential
     */
    public function authenticateClient(string $credentials) : void
    {
        $clientCredential = explode(':', base64_decode($credentials), 2);

        try {
            $this->client = $this->clientStorage->fetch($clientCredential[0]);
            if ($clientCredential[1] !== $this->client->getClientSecret()) {
                throw new InvalidClientCredential('Invalid client identification');
            }
        } catch (NoEntityException $e) {
            throw new InvalidClientCredential('Invalid client secret');
        }
    }

    /**
     * @param array $queryParameters
     * @return bool
     */
    abstract public function validateRequest(array $queryParameters) : bool;

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    abstract public function introspectToken(ServerRequestInterface $request) : bool;

    /**
     * @return array
     */
    abstract public function getResponseArray() : array;

    /**
     * @return array
     */
    public function getErrors() : array
    {
        return $this->errors;
    }

    /**
     * @param string $message
     * @param array $context
     * @return TokenGrantType
     */
    protected function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
