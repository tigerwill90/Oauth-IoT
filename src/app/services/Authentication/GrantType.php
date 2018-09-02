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

abstract class GrantType
{
    /** @var ClientStorageInterface  */
    protected $clientStorage;

    /** @var UserStorageInterface  */
    protected $userStorage;

    public function __construct(ClientStorageInterface $clientStorage, UserStorageInterface $userStorage)
    {
        $this->clientStorage = $clientStorage;
        $this->userStorage = $userStorage;
    }

    abstract public function authenticateClient(array $credentials) : bool;

    abstract public function authenticateUser(string $username, string $password) : bool;

}
