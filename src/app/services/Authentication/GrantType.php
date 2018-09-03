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
use Psr\Http\Message\ServerRequestInterface;

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

    abstract public function authenticateClient(ServerRequestInterface $request) : bool;

    abstract public function authenticateUser(ServerRequestInterface $request) : bool;

}
