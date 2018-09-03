<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:31
 */

namespace Oauth\Services\Validators\Rules;


use Respect\Validation\Validator;

class CredentialRule extends RuleValidator
{

    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::alpha('_')->in(['client_secret','client_identification'])->noWhitespace();
    }
}