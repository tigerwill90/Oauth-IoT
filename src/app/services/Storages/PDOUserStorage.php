<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:22
 */

namespace Oauth\Services\Storage;

use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Users\User;
use Oauth\Services\Users\UserInterface;
use PDO;
use Psr\Log\LoggerInterface;

class PDOUserStorage implements UserStorageInterface
{
    /** @var PDO  */
    private $pdo;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(PDO $pdo, LoggerInterface $logger = null)
    {
        $this->pdo = $pdo;
        $this->logger = $logger;
    }

    /**
     * Fetch a full representation of a user
     * @param $id
     * @return UserInterface
     */
    public function fetch(int $id) : UserInterface
    {
        $sql = 'SELECT use_id AS id, use_username AS username, use_email AS email, use_password AS password, use_refresh_token AS refresh_token_validity FROM users WHERE use_id = ' . $id;

        try {
            $stmt = $this->pdo->query($sql);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data)) {
                throw new NoEntityException('No entity found for this user');
            }
            return new User($data[0]);
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
