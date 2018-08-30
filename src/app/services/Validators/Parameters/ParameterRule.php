<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:02 AM
 */

namespace Oauth\Services\Validators\Parameters;

use Respect\Validation\Validator;

/**
 * Responsibility : now his validators rules
 * Class ParameterRule
 * @package Oauth\Services\Validator\Parameters
 */
abstract class ParameterRule
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
}