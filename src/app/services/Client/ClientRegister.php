<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:44 PM
 */

namespace Oauth\Services\ClientService;

use Psr\Http\Message\ServerRequestInterface;

class ClientRegister
{
    /** @var ClientValidator  */
    private $validator;

    /** @var ClientStorage  */
    private $storage;

    public function __construct(ClientValidator $validator, ClientStorage $storage)
    {
        $this->validator = $validator;
        $this->storage = $storage;
    }

    public function setSecretKeyParameter() : self
    {

    }

    /**
     * @param ServerRequestInterface $request
     * @return ClientRegister
     * @throws
     */
    public function register(ServerRequestInterface $request) : self
    {
        return $this;
    }

    /**
     * @param ServerRequestInterface $request
     * @return ClientRegister
     * @throws
     */
    public function update(ServerRequestInterface $request) : self {
        return $this;
    }

    public function updateSecretKey(ServerRequestInterface $request) : self
    {
        return $this;
    }

    /**
     * @return ClientRegister
     * @throws
     */
    public function unRegister() : self
    {
        return $this;
    }

    /**
     * @return string
     */
    public function getJsonResponse() : string
    {
        return '';
    }
}