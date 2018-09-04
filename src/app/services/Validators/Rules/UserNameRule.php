<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 05.09.2018
 * Time: 00:08
 */

namespace Oauth\Services\Validators\Rules;


use Respect\Validation\Validator;

class UserNameRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::notBlank();
    }
}