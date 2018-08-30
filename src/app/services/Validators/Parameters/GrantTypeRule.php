<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 3:37 PM
 */

namespace Oauth\services\Validators\Parameters;

use Respect\Validation\Validator;

class GrantTypeRule extends ParameterRule
{
    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::in(['code', 'implicit'])->notBlank();
    }
}
