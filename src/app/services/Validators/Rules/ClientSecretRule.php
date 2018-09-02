<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 4:53 PM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class ClientSecretRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::length(8, 50)->notBlank();
    }
}
