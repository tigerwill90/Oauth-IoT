<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:59 PM
 */

namespace Oauth\Services\ClientService;

use PDO;

class PDOClientStorage implements ClientStorageInterface
{
    /** @var PDO  */
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }
}