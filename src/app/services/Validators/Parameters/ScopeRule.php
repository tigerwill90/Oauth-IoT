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
        return Validator::arrayType()->each(Validator::alpha(':')->contains(':')->noWhitespace()->length(3, 30))->notEmpty();
    }

    public function getCustomMessages(): array
    {
        return [
            'arrayType' => '{{name}} : must be a valid array',
            'alpha' => '{{name}} : only letter and {{additionalChars}} are allowed',
            'contains' => '{{name}} : format right:service is expected',
            'noWhitespace' => '{{name}} : must not contains any whitespace',
            'length' => '{{name}} : must be between {{minValue}} and {{maxValue}}',
            'notEmpty' => '{{name}} : must not be empty'
        ];
    }
}
