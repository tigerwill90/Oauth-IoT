<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 07.09.2018
 * Time: 12:03
 */

namespace Oauth\Services\Token;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class TokenManager
{
    /** @var LoggerInterface  */
    private $logger;

    /** @var array */
    private $errors;

    /** @var string */
    private $grantMethod;

    /**
     * <code>
     * $grantType = [
     *      'token' => new ImplicitGrant(),
     *      'response_type' => new AuthorizationGrantType()
     * ]
     * @var TokenGrantType[]
     */
    private $grantType;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * @param string $grantType
     * @param TokenGrantType $tokenGrantType
     * @return TokenManager
     */
    public function add(string $grantType, TokenGrantType $tokenGrantType) : self
    {
        $this->grantType[$grantType] = $tokenGrantType;
        return $this;
    }

    /**
     * Determine if access can be grant
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function grantAccess(ServerRequestInterface $request) : bool
    {
        // Instance have at least one AuthorizationGrantType added
        if (null === $this->grantType) {
            throw new \RuntimeException('Instance should have at least one grant type added');
        }

        $queryParameter = $request->getQueryParams();
        $this->grantMethod = $queryParameter['grant_type'];

        if (null === $this->grantMethod) {
            $this->errors['error'] = 'unsupported_grant_type';
            $this->errors['description'] = 'The request must include a grant type';
            return false;
        }

        if (!array_key_exists($this->grantMethod, $this->grantType)) {
            $this->errors['error'] = 'unsupported_grant_type';
            $this->errors['error_description'] = 'The ' . $this->grantMethod . ' grant type method is not supported by this server';
            return false;
        }

        $authorizations = $request->getHeader('HTTP_AUTHORIZATION');
        $authorization = null;

        if (isset($authorizations[0]) && preg_match('/Basic\s+(.*)$/i', $authorizations[0],$matches)) {
            $authorization =  $matches[1];
        } else {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'Client must authenticate with Basic authentication flow';
            return false;
        }

        try {
            $this->grantType[$this->grantMethod]->authenticateClient($authorization);
        } catch (InvalidClientCredential $e) {
            $this->errors['error'] = 'invalid_client';
            $this->errors['description'] = 'Invalid client identification or secret';
            return false;
        }

        if (!$this->grantType[$this->grantMethod]->validateRequest($queryParameter)) {
            $this->errors = $this->grantType[$this->grantMethod]->getErrors();
            return false;
        }

        if (!$this->grantType[$this->grantMethod]->introspectToken($request)) {
            $this->errors = $this->grantType[$this->grantMethod]->getErrors();
            return false;
        }

        return true;
    }

    /**
     * Return a standardized access granted/error response
     * @return array
     */
    public function getArrayResponse() : array
    {
        return $this->grantType[$this->grantMethod]->getResponseArray();
    }

    /**
     * @return array
     */
    public function getArrayErrors() : array
    {
        if ($this->errors === null) {
            return $this->grantType[$this->grantMethod]->getErrors();
        }
        return $this->errors;
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
