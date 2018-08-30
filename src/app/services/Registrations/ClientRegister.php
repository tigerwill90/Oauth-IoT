<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:44 PM
 */

namespace Oauth\Services\Registrations;

use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\PDOClientStorage;
use RandomLib\Generator;

class ClientRegister
{
    private const COOLDOWN = 5;

    /** @var ClientStorageInterface */
    private $storage;

    /** @var Generator  */
    private $generator;

    /** @var ClientInterface */
    private $client;

    public function __construct(PDOClientStorage $storage, Generator $generator)
    {
        $this->storage = $storage;
        $this->generator = $generator;
    }

    public function register(ClientInterface $client) : self
    {
        $this->client = $client;
        $this->client->setClientSecret($this->generator->generateString(16, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/-_%!?'));
        $this->client->setRegistrationDate(new \DateTime());
        $code = 23000;
        $attemptsNumber = 0;
        while ($code === 23000) {
            try {
                $this->client->setClientId(bin2hex(random_bytes(4)));
                $this->storage->createClient($this->client);
                $code = -1;
            } catch (\PDOException $e) {
                $attemptsNumber++;
                $code = (int)$e->getCode();
                error_log($code . ' ' . $e->getMessage());
                if ($attemptsNumber >= self::COOLDOWN) {
                    throw $e;
                }
                if ($code !== 23000 && $code >= 0) {
                    throw $e;
                }
            }
        }
        return $this;
    }

    public function unRegister(ClientInterface $client) : self
    {
        return $this;
    }

    public function getJsonResponse() : string
    {
        return json_encode($this->client);
    }
}