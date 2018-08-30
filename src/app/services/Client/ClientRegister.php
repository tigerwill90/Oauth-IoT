<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:44 PM
 */

namespace Oauth\Services\ClientService;

// TODO namespace Registration => service
class ClientRegister
{
    /** @var ClientStorageInterface */
    private $storage;

    public function __construct(ClientStorageInterface $storage)
    {
        $this->storage = $storage;
    }

    public function register(ClientInterface $client) : self
    {
        return $this;
    }

    public function unRegister(ClientInterface $client) : self
    {
        return $this;
    }

    public function getJsonResponse() : string
    {
        return null;
    }
}