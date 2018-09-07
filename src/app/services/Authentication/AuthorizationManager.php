<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:49
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Resources\ScopeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Memcached;
use Psr\Log\LoggerInterface;

class AuthorizationManager
{
    /**
     * <code>
     * $grantType = [
     *      'token' => new ImplicitGrant(),
     *      'response_type' => new AuthorizationGrantType()
     * ]
     * @var AuthorizationGrantType[]
     */
    private $grantType;

    /** @var string */
    private $grantMethod;

    /** @var Memcached */
    private $mc;

    /** @var array */
    private $errors = [];

    /** @var string */
    private $redirectUri;

    /** @var string */
    private $queryResponse;

    /** @var LoggerInterface */
    private $logger;

    public function __construct(Memcached $mc, LoggerInterface $logger = null)
    {
        $this->mc = $mc;
        $this->logger = $logger;
    }

    /**
     * @param string $grantResponseType
     * @param AuthorizationGrantType $grantType
     * @return AuthorizationManager
     */
    public function add(string $grantResponseType, AuthorizationGrantType $grantType): self
    {
        $this->grantType[$grantResponseType] = $grantType;
        return $this;
    }

    /**
     * RFC 6749
     * Section 3.1.1 Response type
     * @param ServerRequestInterface $request
     * @return bool
     * @throws NoRedirectErrorException
     */
    public function authorizationRequest(ServerRequestInterface $request): bool
    {
        // Instance have at least one AuthorizationGrantType added
        if (null === $this->grantType) {
            throw new \RuntimeException('Instance should have at least one grant type added');
        }

        $queryParameters = $request->getQueryParams();
        $this->grantMethod = $queryParameters['response_type'];

        // grant type exist
        if (null === $this->grantMethod) {
            reset($this->grantType);
            $this->grantType[key($this->grantType)]->invalidGrantType($queryParameters);
            $this->errors['error'] = 'unsupported_response_type';
            $this->errors['error_description'] = 'The request must include a grant type';
            $this->redirectUri = $this->grantType[key($this->grantType)]->getRedirectUriTarget();
            return false;
        }
        // is supported grant type
        if (!array_key_exists($this->grantMethod, $this->grantType)) {
            reset($this->grantType);
            $this->grantType[key($this->grantType)]->invalidGrantType($queryParameters);
            $this->errors['error'] = 'unsupported_response_type';
            $this->errors['error_description'] = 'The ' . $this->grantMethod . ' response type method is not supported by this server';
            $this->redirectUri = $this->grantType[key($this->grantType)]->getRedirectUriTarget();
            return false;
        }

        try {
            $this->grantType[$this->grantMethod]->authenticateClient($queryParameters);
            $this->grantType[$this->grantMethod]->validateRedirectUri($queryParameters);
            if ($this->grantType[$this->grantMethod]->validateRequest($queryParameters)) {
                try {
                    $this->grantType[$this->grantMethod]->cacheAuthenticationData($this->mc);
                } catch (\ErrorException $e) {
                    $this->errors['error'] = 'server_error';
                    $this->errors['error_description'] = 'The server has encountered an unexpected condition error';
                    return false;
                }
                return true;
            }
        } catch (NoRedirectErrorException $e) {
            throw $e;
        }
        return false;
    }

    /**
     * @param ServerRequestInterface $request
     * @return AuthorizationManager
     * @throws InvalidCredential
     * @throws AuthenticationTimeoutException
     * @throws NoRedirectErrorException
     * @throws SecurityException
     */
    public function authorizationResponse(ServerRequestInterface $request) : self
    {
        // Instance have at least one AuthorizationGrantType added
        if (null === $this->grantType) {
            throw new \RuntimeException('Instance should have at least one grant type added');
        }

        $params = $request->getParsedBody();
        $cache = $this->mc->get($params['unique_identifier']);

        // session exist
        if (empty($cache)) {
            throw new AuthenticationTimeoutException('This session has expired');
        }

        $this->grantMethod = $cache['grant_method'];

        $this->grantType[$this->grantMethod]->populateFromCache($params['unique_identifier'], $cache);

        // anti CSRF (maybe not relevant)
        if ($cache['token_authenticity'] !== $params['token_authenticity']) {
            throw new SecurityException('The authenticity of the session is compromised');
        }

        // authenticate user
        try {
            $this->grantType[$this->grantMethod]->validateScope($params);
            $this->grantType[$this->grantMethod]->authenticateUser($params);
        } catch (InvalidCredential $e) {
            $this->grantType[$this->grantMethod]->updateCache($params['unique_identifier'], $this->mc);
            throw $e;
        } catch (NoRedirectErrorException $e) {
            $this->grantType[$this->grantMethod]->updateCache($params['unique_identifier'], $this->mc);
            throw $e;
        }
        $this->queryResponse = $this->grantType[$this->grantMethod]->getQueryResponse($cache);
        return $this;
    }

    /**
     * @return string
     */
    public function getUniqueIdentifier(): string
    {
        return $this->grantType[$this->grantMethod]->getUniqueIdentifier();
    }

    /**
     * @return string
     */
    public function getTokenAuthenticity(): string
    {
        return $this->grantType[$this->grantMethod]->getTokenAuthenticity();
    }

    /**
     * @return ScopeInterface[]
     */
    public function getResourceScope(): array
    {
        return $this->grantType[$this->grantMethod]->getResource()->getScope();
    }

    /**
     * @return string
     */
    public function getClientName(): string
    {
        return $this->grantType[$this->grantMethod]->getClient()->getClientName();
    }

    /**
     * @return array
     */
    public function getErrorsMessages() : array
    {
        if (null === $this->grantMethod || !array_key_exists($this->grantMethod, $this->grantType)) {
            return $this->errors;
        }
        $error = $this->grantType[$this->grantMethod]->getErrorsMessages();
        if (!empty($error)) {
            return $error;
        }
        return $this->errors;
    }

    /**
     * @return string
     */
    public function getQueryResponse() : string
    {
        return $this->queryResponse;
    }

    /**
     * RFC 6749
     * Section 3.1.2 Redirection endpoint and url encoding style
     * @return string
     */
    public function getQueryErrorResponse() : string
    {
        return http_build_query($this->getErrorsMessages(), null, '&', PHP_QUERY_RFC3986);
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

    /**
     * @param string $message
     * @param array $context
     * @return AuthorizationManager
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
