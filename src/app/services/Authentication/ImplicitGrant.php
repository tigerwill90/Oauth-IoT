<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authentication;


class ImplicitGrant extends GrantType
{

    public function authenticateClient(array $credentials): bool
    {
        // TODO: Implement authenticateClient() method.
    }

    public function authenticateUser(string $username, string $password): bool
    {
        // TODO: Implement authenticateUser() method.
    }
}