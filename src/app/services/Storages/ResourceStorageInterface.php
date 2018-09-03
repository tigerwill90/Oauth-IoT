<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:20 PM
 */

namespace Oauth\Services\Storage;


use Oauth\Services\Resources\ResourceInterface;

interface ResourceStorageInterface
{
    public function fetchByAudience(string $audience) : ResourceInterface;
}