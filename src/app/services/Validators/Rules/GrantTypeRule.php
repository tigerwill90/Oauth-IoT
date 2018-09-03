<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 3:37 PM
 */

namespace Oauth\services\Validators\Rules;

use Respect\Validation\Validator;

class GrantTypeRule extends RuleValidator
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::in(['code', 'implicit'])->notBlank()->noWhitespace();
    }
}
