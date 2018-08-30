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
    public function createClient($client) : void;

}