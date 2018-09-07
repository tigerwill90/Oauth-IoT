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
    /**
     * @param int $id
     * @return UserInterface
     */
    public function fetch(int $id) : UserInterface;

    /**
     * @param string $identity
     * @return UserInterface
     */
    public function fetchByUsername(string $identity) : UserInterface;
}
