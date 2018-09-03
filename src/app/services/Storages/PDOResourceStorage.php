<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:19 PM
 */

namespace Oauth\Services\Storage;


use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Resources\ResourceInterface;
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

    public function fetchByAudience(string $audience): ResourceInterface
    {
        $sql =
            '
                SELECT 
                  res_id AS id, res_identification AS resource_identification, res_secret AS resource_secret, res_audience AS resource_audience, res_registration_date AS resource_registration_date, res_pop_method AS resource_pop_method,
                   res_sco_service AS scope_service, res_sco_description AS scope_description, res_sco_url AS scope_url, res_sco_name AS scope_name
                  FROM resources 
                  JOIN scopes ON res_id = res_sco_res_id
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
            $temp = [];
            foreach ($data as $i => $iValue) {
                $key = substr($iValue, 0, 5);
                if ($key === 'scope') {
                    $temp[$i] = $iValue;
                }
            }
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