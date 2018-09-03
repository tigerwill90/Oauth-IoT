<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:49
 */

namespace Oauth\Services\Authentication;

use Psr\Http\Message\ServerRequestInterface;

class AuthenticationManager
{

    /**
     * <code>
     * $grantType = [
     *      'token' => new ImplicitGrant(),
     *      'response_type' => new GrantType()
     * ]
     * @var array[string]GrantType
     */
    private $grantType;

    /** @var array */
    private $queryParams;

    public function __construct()
    {
    }

    /**
     * @param string $grantResponseType
     * @param GrantType $grantType
     * @return AuthenticationManager
     */
    public function add(string $grantResponseType, GrantType $grantType) : self
    {
        $this->grantType[$grantResponseType] = $grantType;
        return $this;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function authenticateClient(ServerRequestInterface $request) : bool
    {

        $this->queryParams = $request->getQueryParams();
        // is supported grant type
        if (null === $this->queryParams ['response_type'] || !array_key_exists($this->queryParams ['response_type'], $this->grantType)) {
            throw new \InvalidArgumentException('This response type : [' . $this->queryParams ['response_type'] .  '] is not supported');
        }
        return $this->grantType[$this->queryParams ['response_type']]->authenticateClient($this->queryParams );
    }

    /**
     * @return string
     */
    public function retrieveStateArguments() : string
    {
        return $this->grantType[$this->queryParams['response_type']]->getStateFromCache();
    }

    /**
     * @return array
     */
    public function getMessages() : array
    {
        $errors['errors'] = $this->grantType[$this->queryParams['response_type']]->getMessages();
        return $errors;
    }
}
