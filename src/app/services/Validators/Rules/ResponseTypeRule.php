<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 3:26 PM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class ResponseTypeRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::in(['token', 'code'])->notBlank()->noWhitespace();
    }
}
