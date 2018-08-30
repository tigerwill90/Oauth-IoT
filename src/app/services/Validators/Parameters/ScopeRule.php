<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 5:05 PM
 */

namespace Oauth\Services\Validators\Parameters;

use Respect\Validation\Validator;

class ScopeRule extends ParameterRule
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::arrayType()->each(Validator::alpha('_')->noWhitespace()->length(3, 30))->notEmpty();
    }
}
