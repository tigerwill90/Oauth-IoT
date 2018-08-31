<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:37 PM
 */

namespace Oauth\Services\Storage;

interface ClientStorageInterface
{
    public function create($client) : void;

    public function delete(string $clientId) : void;
}