<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:27 PM
 */

namespace Oauth\Services\Introspection;

class ClaimsCheckerRules implements ClaimsCheckerInterface
{

    // Necessary stuff to perform claims verification
    public function __construct()
    {
    }

    public function verifySub(string $sub) : bool
    {
        return false;
    }

    public function verifyAud(string $aud) : bool
    {
        return $aud === 'Your application';
    }

    public function verifyIss(string $iss) : bool
    {
        return $iss === 'My service';
    }

    public function verifyJti(string $jti) : bool
    {
        return $jti !== 'nonce';
    }

    public function verifyScope(string $scope) : bool
    {
        return false;
    }
}
