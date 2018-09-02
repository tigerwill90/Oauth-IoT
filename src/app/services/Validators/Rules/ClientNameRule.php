<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:04 AM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class ClientNameRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::length(3, 80)->notBlank()->graph(' ');
    }
}
