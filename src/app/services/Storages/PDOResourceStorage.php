<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:19 PM
 */

namespace Oauth\Services\Storage;


use Oauth\Services\Clients\Client;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Resources\Resource;
use Oauth\Services\Resources\ResourceInterface;
use Oauth\Services\Resources\Scope;
use Oauth\Services\Resources\ScopeInterface;
use Psr\Log\LoggerInterface;
use PDO;

class PDOResourceStorage implements ResourceStorageInterface
{
    /** @var PDO  */
    private $pdo;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(PDO $pdo, LoggerInterface $logger)
    {
        $this->pdo = $pdo;
        $this->logger = $logger;
    }

    /**
     * Return a full representation of a resource with it's respective scope
     * @param string $identification
     * @return ResourceInterface
     */
    public function fetchByResourceIdentification(string $identification) : ResourceInterface
    {
        $sql =
            '
                SELECT 
                   res_id AS id, res_identification AS resource_identification, res_secret AS resource_secret, res_audience AS resource_audience, res_registration_date AS resource_registration_date,
                   res_pop_method AS resource_pop_method, res_key_size AS key_size, res_algorithm_encryption AS shared_key_algorithm, res_tls AS tls, res_transmission_algorithm AS transmission_algorithm,
                   res_sco_service AS scope_service, res_sco_description AS scope_description, res_sco_uri AS scope_uri, res_sco_name AS scope_name, res_sco_method AS scope_method
                  FROM resources 
                  JOIN resources_scopes ON res_id = res_sco_res_id
                  WHERE res_identification = :identification
            ';

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':identification', $identification);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data)) {
                throw new NoEntityException('No entity found for this resource identification : ' . $identification);
            }

            $scopes = [];
            foreach ($data as $scope) {
                $scopes[] = new Scope($scope);
            }

            $resource = new Resource($data[0]);
            return $resource->setScope($scopes);
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * Return a full representation of a resource with it's respective scope
     * @param string $audience
     * @return ResourceInterface
     */
    public function fetchByAudience(string $audience): ResourceInterface
    {
        $sql =
            '
                SELECT 
                   res_id AS id, res_identification AS resource_identification, res_secret AS resource_secret, res_audience AS resource_audience, res_registration_date AS resource_registration_date,
                   res_pop_method AS resource_pop_method, res_key_size AS key_size, res_algorithm_encryption AS shared_key_algorithm, res_tls AS tls, res_transmission_algorithm AS transmission_algorithm,
                   res_sco_service AS scope_service, res_sco_description AS scope_description, res_sco_uri AS scope_uri, res_sco_name AS scope_name, res_sco_method AS scope_method
                  FROM resources 
                  JOIN resources_scopes ON res_id = res_sco_res_id
                  WHERE res_audience = :audience
            ';

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':audience', $audience);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data)) {
                throw new NoEntityException('No entity found for this resource : ' . $audience);
            }

            $scopes = [];
            foreach ($data as $scope) {
                $scopes[] = new Scope($scope);
            }

            $resource = new Resource($data[0]);
            return $resource->setScope($scopes);
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param string $service
     * @return ScopeInterface
     */
    public function fetchScopeByService(string $service) : ScopeInterface
    {
        $sql = 'SELECT 
                  res_sco_id AS id ,res_sco_service AS scope_service, res_sco_description AS scope_description, res_sco_uri AS scope_uri, res_sco_name AS scope_name, res_sco_method AS scope_method 
                  FROM resources_scopes WHERE res_sco_service = :service';

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':service', $service);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (empty($data)) {
                throw new NoEntityException('No entity found for this scope service : ' . $service);
            }
            return new Scope($data[0]);
        } catch (\PDOException $e) {
            throw $e;
        }
    }

    /**
     * @param string $message
     * @param array $context
     * @return PDOResourceStorage
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}