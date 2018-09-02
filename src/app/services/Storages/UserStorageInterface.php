<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:23
 */

namespace Oauth\Services\Storage;

use Oauth\Services\Users\UserInterface;

interface UserStorageInterface
{
    public function fetchById(int $id) : UserInterface;
}
