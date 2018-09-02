<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:44 PM
 */

namespace Oauth\Services\Validators;

use Oauth\Services\Validators\Rules\RuleValidator;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

abstract class Validator
{
    /** @var string[] */
    protected $requiredErrors = [];

    /** @var string[] */
    protected $validatorErrors = [];

    /**
     * Add a new RuleValidator
     * @param string $field
     * @param RuleValidator $parameterRule
     * @return Validator
     */
    abstract public function add(string $field, RuleValidator $parameterRule) : Validator;

    abstract public function checkExist(ServerRequestInterface $request): bool;

    abstract public function validate(ServerRequestInterface $request): bool;

    public function getErrorsMessages() : array
    {
        return array_merge($this->requiredErrors, $this->validatorErrors);
    }
}