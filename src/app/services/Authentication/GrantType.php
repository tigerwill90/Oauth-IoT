<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:01
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\UserStorageInterface;
use Memcached;
use Psr\Http\Message\ServerRequestInterface;

abstract class GrantType
{
    /** @var ClientStorageInterface  */
    protected $clientStorage;

    /** @var UserStorageInterface  */
    protected $userStorage;

    /** @var array */
    protected $errorsMessages = [];

    /** @var Memcached  */
    protected $mc;

    public function __construct(ClientStorageInterface $clientStorage, UserStorageInterface $userStorage, Memcached $mc)
    {
        $this->clientStorage = $clientStorage;
        $this->userStorage = $userStorage;
        $this->mc = $mc;
    }

    /**
     * Authenticate a client
     * @param array $queryParameters
     * @return bool
     */
    abstract public function authenticateClient(array $queryParameters) : bool;

    /**
     * Authenticate a user
     * @param ServerRequestInterface $request
     * @return bool
     */
    abstract public function authenticateUser(ServerRequestInterface $request) : bool;

    /**
     * @param string $clientId
     * @return string
     */
    public function getStateFromCache(string $clientId) : string
    {
        $state = $this->mc->get('auth_state:' . $clientId);
        $this->mc->delete('auth_state:' . $clientId);
        return $state;
    }

    /**
     * @return array
     */
    public function getMessages() : array
    {
        return $this->errorsMessages;
    }
}
