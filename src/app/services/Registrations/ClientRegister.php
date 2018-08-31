<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:44 PM
 */

namespace Oauth\Services\Registrations;

use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Exceptions\Storage\ClientIdException;
use Oauth\Services\Exceptions\Storage\StorageException;
use Oauth\Services\Exceptions\Storage\UniqueException;
use Oauth\Services\Exceptions\ValidatorException;
use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\PDOClientStorage;
use Psr\Log\LoggerInterface;
use RandomLib\Generator;

class ClientRegister
{
    private const COOL_DOWN = 5;

    private const PASSWORD_CHAR = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/-_%!?${}[]';

    private const CLIENT_IDENTIFIER_CHAR = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** @var ClientStorageInterface */
    private $storage;

    /** @var Generator  */
    private $generator;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(PDOClientStorage $storage, Generator $generator, LoggerInterface $logger = null)
    {
        $this->storage = $storage;
        $this->generator = $generator;
        $this->logger = $logger;
    }

    /**
     * Generate credentials and register a new client
     * @param ClientInterface $client
     * @return ClientRegister
     * @throws ValidatorException
     */
    public function register(ClientInterface $client) : self
    {
        $client->setClientSecret($this->generator->generateString(16, self::PASSWORD_CHAR));
        $client->setRegistrationDate(new \DateTime());
        // Not sur than this is in right way
        $client->setScope(array_unique($client->getScope()));
        $attemptsNumber = 0;
        $exception = true;
        while ($exception) {
            $client->setClientId($this->generator->generateString(8, self::CLIENT_IDENTIFIER_CHAR));
            try {
                $this->storage->create($client);
                $exception = false;
            } catch (ClientIdException $e) {
                $attemptsNumber++;
                $this->log('ClientIdException', ['context' => 'ClientRegister','code' => $e->getCode(), 'message' => $e->getMessage()]);
                if ($attemptsNumber >= self::COOL_DOWN) {
                    throw new ValidatorException($e->getMessage(), $e->getCode());
                }
            } catch (UniqueException $e) {
                $this->log('UniqueException', ['context' => 'ClientRegister','code' => $e->getCode(), 'message' => $e->getMessage()]);
                throw new ValidatorException($e->getMessage(), $e->getCode());
            } catch (\PDOException $e) {
                throw $e;
            }
        }
        return $this;
    }

    /**
     * @param string $clientId
     * @return ClientRegister
     */
    public function unRegister(string $clientId) : self
    {
        try {
            $this->storage->delete($clientId);
        } catch (StorageException $e) {
            throw $e;
        }
        return $this;
    }

    /**
     * @param string $message
     * @param array $context
     * @return ClientRegister
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}