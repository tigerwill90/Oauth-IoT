<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 3:31 PM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

class QScopeRule extends RuleValidator
{

    /**
     * Get a validator instance
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return Validator::alpha(':')->contains(':')->notBlank();
    }

    public function getCustomMessages(): array
    {
        return [
            'alpha' => '{{name}} : only letter and {{additionalChars}} are allowed',
            'contains' => '{{name}} : format right:service is expected',
            'notBlank' => '{{name}} : must not be blank'
        ];
    }
}