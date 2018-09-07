<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 05.09.2018
 * Time: 18:42
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class TokenRule extends RuleValidator
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
