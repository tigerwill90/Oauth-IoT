<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:49
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Resources\ScopeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Memcached;
use Psr\Log\LoggerInterface;
use RandomLib\Generator;

class AuthenticationManager
{
    private const TOKEN_CHAR_GEN = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    private const COOL_DOWN = 5;
    /**
     * <code>
     * $grantType = [
     *      'token' => new ImplicitGrant(),
     *      'response_type' => new GrantType()
     * ]
     * @var GrantType[]
     */
    private $grantType;

    /** @var string */
    private $grantMethod;

    /** @var Memcached */
    private $mc;

    /** @var Generator */
    private $generator;

    /** @var string */
    private $tokenAuthenticity;

    /** @var string */
    private $uniqueIdentifier;

    /** @var array */
    private $errors = [];

    /** @var string */
    private $redirectUri;

    /** @var LoggerInterface */
    private $logger;

    public function __construct(Memcached $mc, Generator $generator, LoggerInterface $logger = null)
    {
        $this->mc = $mc;
        $this->generator = $generator;
        $this->logger = $logger;
    }

    /**
     * @param string $grantResponseType
     * @param GrantType $grantType
     * @return AuthenticationManager
     */
    public function add(string $grantResponseType, GrantType $grantType): self
    {
        $this->grantType[$grantResponseType] = $grantType;
        return $this;
    }

    /**
     * RFC 6749
     * Section 3.1.1 Response type
     * @param ServerRequestInterface $request
     * @return bool
     * @throws \ErrorException
     * @throws NoRedirectErrorException
     */
    public function authorizeClient(ServerRequestInterface $request): bool
    {
        // Instance have at least one GrantType added
        if (null === $this->grantType) {
            throw new \RuntimeException('Instance should have at least one grant type added');
        }

        $this->grantMethod = $request->getQueryParams()['response_type'];
        if ($this->grantMethod === null) {
            $this->grantMethod = $request->getParsedBody()['grant_type'];
        }

        // grant type exist
        if (null === $this->grantMethod) {
            reset($this->grantType);
            $this->grantType[key($this->grantType)]->invalidGrantType($request);
            $this->errors['type'] = 'unsupported_response_type';
            $this->errors['description'] = 'The request must include a grant type';
            $this->redirectUri = $this->grantType[key($this->grantType)]->getRedirectUriTarget();
            return false;
        }
        // is supported grant type
        if (!array_key_exists($this->grantMethod, $this->grantType)) {
            reset($this->grantType);
            $this->grantType[key($this->grantType)]->invalidGrantType($request);
            $this->errors['type'] = 'unsupported_response_type';
            $this->errors['description'] = 'The ' . $this->grantMethod . ' response type method is not supported by this server';
            $this->redirectUri = $this->grantType[key($this->grantType)]->getRedirectUriTarget();
            return false;
        }

        try {
            $this->grantType[$this->grantMethod]->authenticateClient($request);
            if ($this->grantType[$this->grantMethod]->validateRequest($request)) {
                $this->tokenAuthenticity = $this->generator->generateString(32, self::TOKEN_CHAR_GEN);
                // Get a unique identifier
                $break = 0;
                while (true) {
                    $uniqueIdentifier = $this->generator->generateString(8, self::TOKEN_CHAR_GEN);
                    if (empty($this->mc->get($uniqueIdentifier))) {
                        $this->uniqueIdentifier = $uniqueIdentifier;
                        break;
                    }
                    if ($break >= self::COOL_DOWN) {
                        throw new \ErrorException('Impossible to create a unique identifier');
                    }
                    $break++;
                }
                $this->grantType[$this->grantMethod]->cacheAuthenticationData($request, $this->mc, $this->uniqueIdentifier, $this->tokenAuthenticity);
                return true;
            }
        } catch (NoRedirectErrorException $e) {
            throw $e;
        }
        return false;
    }

    public function authorizeUser(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        // Instance have at least one GrantType added
        if (null === $this->grantType) {
            throw new \RuntimeException('Instance should have at least one grant type added');
        }
    }

    /**
     * @return string
     */
    public function getUniqueIdentifier(): string
    {
        return $this->uniqueIdentifier;
    }

    /**
     * @return string
     */
    public function getTokenAuthenticity(): string
    {
        return $this->tokenAuthenticity;
    }

    /**
     * @param string $uniqueIdentifier
     * @return string
     * @throws AuthenticationTimeoutException
     */
    public function getTokenAuthenticityFromCache(string $uniqueIdentifier): string
    {
        $cache = $this->mc->get($uniqueIdentifier);
        if (empty($cache) || empty($cache['token_authenticity'])) {
            throw new AuthenticationTimeoutException('Token authenticity not found, connexion expired');
        }
        return $cache['token_authenticity'];
    }

    /**
     * @return ScopeInterface[]
     */
    public function getResourceScope(): array
    {
        return $this->grantType[$this->grantMethod]->getResource()->getScope();
    }

    /**
     * @param string $uniqueIdentifier
     * @return array
     * @throws AuthenticationTimeoutException
     */
    public function getResourceScopeFromCache(string $uniqueIdentifier): array
    {
        $cache = $this->mc->get($uniqueIdentifier);
        if (empty($cache) || empty($cache['resource'])) {
            throw new AuthenticationTimeoutException('Resource not found, connexion expired');
        }
        $resource = (object)$cache['resource'];
        return $resource->getScope();
    }

    /**
     * @return string
     */
    public function getClientName(): string
    {
        return $this->grantType[$this->grantMethod]->getClient()->getClientName();
    }

    /**
     * @param string $uniqueIdentifier
     * @return string
     * @throws AuthenticationTimeoutException
     */
    public function getClientNameFromCache(string $uniqueIdentifier): string
    {
        $cache = $this->mc->get($uniqueIdentifier);
        if (empty($cache) || empty($cache['client'])) {
            throw new AuthenticationTimeoutException('Client not found, connexion expired');
        }
        $client = (object)$cache['client'];
        return $client->getClientName();
    }

    /**
     * @param string $uniqueIdentifier
     * @return string
     * @throws AuthenticationTimeoutException
     */
    public function getStateFromCache(string $uniqueIdentifier): string
    {
        $cache = $this->mc->get($uniqueIdentifier);
        if (empty($cache) || empty($cache['state'])) {
            throw new AuthenticationTimeoutException('State not found, connexion expired');
        }
        return $cache['state'];
    }

    /**
     * @return array
     */
    public function getErrorsMessages() : array
    {
        if (null === $this->grantMethod || !array_key_exists($this->grantMethod, $this->grantType)) {
            return $this->errors;
        }
        return $this->grantType[$this->grantMethod]->getErrorsMessages();
    }

    /**
     * @return string
     */
    public function getRedirectionUri(): string
    {
        if (null === $this->grantMethod || !array_key_exists($this->grantMethod, $this->grantType)) {
            return $this->redirectUri;
        }
        return $this->grantType[$this->grantMethod]->getRedirectUriTarget();
    }

    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
