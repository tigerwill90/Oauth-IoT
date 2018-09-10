<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:20 PM
 */

namespace Oauth\Services\Storage;

use Oauth\Services\Resources\ResourceInterface;
use Oauth\Services\Resources\ScopeInterface;

interface ResourceStorageInterface
{

    /**
     * Return a full representation of a resource with it's respective scope
     * @param string $identification
     * @return ResourceInterface
     */
    public function fetchByResourceIdentification(string $identification) : ResourceInterface;

    /**
     * Return a full representation of a resource with it's respective scope
     * @param string $audience
     * @return ResourceInterface
     */
    public function fetchByAudience(string $audience): ResourceInterface;

    /**
     * @param string $service
     * @return ScopeInterface
     */
    public function fetchScopeByService(string $service) : ScopeInterface;
}