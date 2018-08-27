<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:27 PM
 */

namespace Oauth\Services\Introspection;


class IExtended implements ClaimsCheckerInterface
{

    // this should take a dao class here
    public function __construct()
    {
    }

    public function getUserInformation(array $claims): string
    {
        return 'toto';
    }

    public function verifySub(string $sub): bool
    {
       return false;
    }

    public function verifyAud(string $aud): bool
    {
        return $aud === 'Your application';
    }

    public function verifyIss(string $iss): bool
    {
        return $iss === 'My service';
    }

    public function verifyJti(string $jti): bool
    {
        return false;
    }

    public function verifyScope(string $scope): bool
    {
        return false;
    }
}