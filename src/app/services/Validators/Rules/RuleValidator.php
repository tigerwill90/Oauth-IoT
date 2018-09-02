<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:02 AM
 */

namespace Oauth\Services\Validators\Rules;

use Respect\Validation\Validator;

/**
 * Responsibility : now his validators rules
 * Class RuleValidator
 * @package Oauth\Services\Validator\Parameters
 */
abstract class RuleValidator
{
    /** @var bool */
    protected $required;

    public function __construct($required = true)
    {
        $this->required = $required;
    }

    /**
     * Is a mandatory request parameter
     * @return bool
     */
    public function isRequired() : bool
    {
        return $this->required;
    }

    /**
     * Get a validator instance
     * @return Validator
     */
    abstract public function getValidator(): Validator;

    /**
     * Get custom validator errors
     * @return array
     */
    public function getCustomMessages() : array {
        return [];
    }
}
