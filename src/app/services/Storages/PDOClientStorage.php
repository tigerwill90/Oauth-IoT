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
use PDO;

class PDOClientStorage implements ClientStorageInterface
{
    /** @var PDO  */
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * @param Client $client
     */
    public function createClient($client) : void
    {
        $sql =
            '
                INSERT INTO clients (cli_client_id, cli_client_secret, cli_client_name, cli_grant_type, cli_client_type, cli_registration_date) 
                VALUES (:clientId, :clientSecret, :clientName, :grantType, :clientType, :registrationDate)
            ';

        try {
            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':clientId',$client->getClientId());
            $stmt->bindParam(':clientSecret', $client->getClientSecret());
            $stmt->bindParam(':clientName', $client->getClientName());
            $stmt->bindParam(':grantType', $client->getGrantType());
            $stmt->bindParam(':clientType', $client->getClientType());
            $stmt->bindParam(':registrationDate', $client->getRegistrationDate());
            $stmt->execute();
            $client->setId($this->pdo->lastInsertId());
            $this->pdo->commit();
        } catch (\PDOException $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    private function writeScope(array $scope) : void
    {

    }

    private function writeRedirectUrl(array $scope) : void
    {

    }

    public function getClient(int $clientId): ClientInterface
    {

    }
}