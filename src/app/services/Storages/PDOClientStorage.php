<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:59 PM
 */

namespace Oauth\Services\Storage;

use Oauth\Services\Clients\Client;
use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Exceptions\Storage\ClientIdException;
use Oauth\Services\Exceptions\Storage\ClientSecretException;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Exceptions\Storage\UniqueException;
use PDO;
use Psr\Log\LoggerInterface;

class PDOClientStorage implements ClientStorageInterface
{
    private const SQLSTATE_23000 = 23000;

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
     * @param string $clientId
     * @return ClientInterface
     */
    public function fetch(string $clientId) : ClientInterface
    {
        $sql =
            '
              SELECT 
                cli_id AS id, cli_client_identification AS client_identification, cli_client_secret AS client_secret, cli_client_name AS client_name, cli_grant_type AS grant_type, 
                cli_client_type AS client_type, cli_registration_date AS registration_date, sco_service AS scope, red_url AS redirect_url
              FROM clients 
              JOIN clients_scopes ON cli_id = sco_cli_id
              JOIN redirect_uri ON cli_id = red_cli_id
              WHERE cli_client_identification = :clientId
            ';

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':clientId', $clientId);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data)) {
                throw new NoEntityException('No entity found for this client ' . $clientId);
            }
            $scopes = [];
            $uri = [];
            foreach ($data as $i => $iValue) {
                $scopes[] = $data[$i]['scope'];
                $uri[] = $data[$i]['redirect_url'];
            }

            $data[0]['scope'] = array_unique($scopes);
            $data[0]['redirect_uri'] = array_unique($uri);

            return new Client($data[0]);
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param Client $client
     */
    public function create($client) : void
    {
        $sql =
            '
                INSERT INTO clients (cli_client_identification, cli_client_secret, cli_client_name, cli_grant_type, cli_client_type, cli_registration_date) 
                VALUES (:clientId, :clientSecret, :clientName, :grantType, :clientType, :registrationDate)
            ';

        try {
            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare($sql);
            $clientId = $client->getClientIdentification();
            $stmt->bindParam(':clientId',$clientId);
            $clientSecret = $client->getClientSecret();
            $stmt->bindParam(':clientSecret', $clientSecret);
            $clientName = $client->getClientName();
            $stmt->bindParam(':clientName', $clientName);
            $grantType = $client->getGrantType();
            $stmt->bindParam(':grantType', $grantType);
            $clientType = $client->getClientType();
            $stmt->bindParam(':clientType', $clientType);
            $registrationDate = $client->getRegistrationDate();
            $stmt->bindParam(':registrationDate', $registrationDate);
            $stmt->execute();
            $client->setId($this->pdo->lastInsertId());
            $this->writeScope($client->getId(), $client->getScope());
            $this->writeRedirectUrl($client->getId(), $client->getRedirectUri());
            $this->pdo->commit();
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === self::SQLSTATE_23000) {
                if (strpos($e->getMessage(), $client->getClientIdentification()) !== false) {
                    $this->pdo->rollBack();
                    throw new ClientIdException('This client id already exist', $e->getCode());
                }
                if (strpos($e->getMessage(), $client->getClientName()) !== false) {
                    $this->pdo->rollBack();
                    throw new UniqueException('This client name already exist', $e->getCode());
                }
            }
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * @param int $id
     * @param array $scopes
     */
    private function writeScope(int $id ,array $scopes) : void
    {
        $sql ='INSERT INTO clients_scopes (sco_service, sco_cli_id) VALUES (:service, :fkId)';

        try {
            $stmt = $this->pdo->prepare($sql);
            foreach ($scopes as $scope) {
                $stmt->bindParam(':service', $scope);
                $stmt->bindParam(':fkId', $id);
                $stmt->execute();
            }
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param int $id
     * @param array $urls
     */
    private function writeRedirectUrl(int $id, array $urls) : void
    {
        $sql = 'INSERT INTO redirect_uri (red_url, red_cli_id) VALUES (:url, :fkId)';
        try {
            $stmt = $this->pdo->prepare($sql);
            foreach ($urls as $url) {
                $stmt->bindParam(':url', $url);
                $stmt->bindParam('fkId', $id);
                $stmt->execute();
            }
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === self::SQLSTATE_23000) {
                throw new UniqueException('This url already exist', $e->getCode());
            }
            throw $e;
        }

    }

    /**
     * @param string $clientId
     */
    public function delete(string $clientId) : void
    {

        $sql = 'DELETE FROM clients WHERE cli_client_identification = :clientId';

        try {
            $this->pdo->beginTransaction();
            $clientRowId = $this->getClientRowId($clientId);
            $this->deleteItem('DELETE FROM clients_scopes WHERE sco_cli_id = ' . $clientRowId);
            $this->deleteItem('DELETE FROM redirect_uri WHERE red_cli_id = ' . $clientRowId);
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':clientId', $clientId);
            $stmt->execute();
            $this->pdo->commit();
            if ($stmt->rowCount() === 0) {
                throw new NoEntityException('No entity found for this client : ' . $clientId);
            }
        } catch (\PDOException $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * @param string $clientId
     * @return int
     */
    private function getClientRowId(string $clientId) : int {
        $sql = 'SELECT cli_id AS id FROM clients WHERE cli_client_identification = :clientId';
        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam('clientId', $clientId);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data[0]['id'])) {
                throw new NoEntityException('No entity found for this client : ' . $clientId);
            }
            return $data[0]['id'];
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param string $sql
     */
    private function deleteItem(string $sql) : void
    {
        try {
            $stmt = $this->pdo->query($sql);
            $stmt->execute();
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * Update all no-autogenerated client field (aka client_identification, client_secret, registration_date)
     * @param Client $client
     */
    public function update($client): void
    {
        $sql =
            '
                UPDATE clients SET 
                    cli_client_name = :clientName, 
                    cli_grant_type = :grantType, 
                    cli_client_type = :clientType
                WHERE cli_client_identification = :clientId
            ';

        $currentClient = $this->fetch($client->getClientIdentification());
        $client->setClientSecret($currentClient->getClientSecret());
        $client->setRegistrationDate(new \DateTime($currentClient->getRegistrationDate()));

        try {
            $this->pdo->beginTransaction();

            // Rewrite scope table only if needed
            if (!$this->arrayEquals($client->getScope(), $currentClient->getScope())) {
                $this->deleteItem('DELETE FROM clients_scopes WHERE sco_cli_id = ' . $currentClient->getId());
                $this->writeScope($currentClient->getId(), $client->getScope());
            }

            // Rewrite redirect url table only if needed
            if (!$this->arrayEquals($client->getRedirectUri(), $currentClient->getRedirectUri())) {
                $this->deleteItem('DELETE FROM redirect_uri WHERE red_cli_id = ' . $currentClient->getId());
                $this->writeRedirectUrl($currentClient->getId(), $client->getRedirectUri());
            }

            $stmt = $this->pdo->prepare($sql);
            $clientName = $client->getClientName();
            $stmt->bindParam(':clientName', $clientName);
            $grantType = $client->getGrantType();
            $stmt->bindParam(':grantType', $grantType);
            $clientType = $client->getGrantType();
            $stmt->bindParam(':clientType', $clientType);
            $clientId = $client->getClientIdentification();
            $stmt->bindParam(':clientId', $clientId);
            $stmt->execute();
            $this->pdo->commit();
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === self::SQLSTATE_23000 && strpos($e->getMessage(), $client->getClientName()) !== false) {
                $this->pdo->rollBack();
                throw new UniqueException('This client name already exist', $e->getCode());
            }
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * @param string $currentClientId
     * @param string $newClientId
     * @return ClientInterface
     */
    public function updateIdentification(string $currentClientId, string $newClientId): ClientInterface
    {
        $sql = 'UPDATE clients SET cli_client_identification = :newClientId WHERE cli_client_identification = :currentClientId';
        $client = $this->fetch($currentClientId);

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':newClientId', $newClientId);
            $stmt->bindParam('currentClientId', $currentClientId);
            $stmt->execute();
            if ($stmt->rowCount() === 0) {
                throw new ClientIdException('The client id has not changed');
            }
            return $client;
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === self::SQLSTATE_23000 && strpos($e->getMessage(), $newClientId) !== false) {
                throw new ClientIdException('This client id already exist', $e->getCode());
            }
            throw $e;
        }
    }

    /**
     * @param string $clientId
     * @param string $newSecret
     * @return ClientInterface
     */
    public function updateSecret(string $clientId, string $newSecret): ClientInterface
    {
        $sql = 'UPDATE clients SET cli_client_secret = :newSecret WHERE cli_client_identification = :clientId';
        $client = $this->fetch($clientId);

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':newSecret', $newSecret);
            $stmt->bindParam('clientId', $clientId);
            $stmt->execute();
            if ($stmt->rowCount() === 0) {
                throw new ClientSecretException('The client secret has not changed');
            }
            return $client;
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param string $message
     * @param array $context
     * @return PDOClientStorage
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}