<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:44
 */

namespace Oauth\Services\Validators;


use Oauth\Services\Validators\Rules\RuleValidator;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class ParameterValidator extends Validator
{
    /**
     * <code>
     * $parametersValidator = [
     *      'client_id' => new ClientNameRule(true),
     *      'parameter' => RuleValidator
     * ]
     * @var array[string]RuleValidator
     */
    protected $parametersValidator;

    public function __construct()
    {
    }

    /**
     * Add a new RuleValidator
     * @param string $parameter
     * @param RuleValidator $parameterRule
     * @return Validator
     */
    public function add(string $parameter, RuleValidator $parameterRule): Validator
    {
        $this->parametersValidator[$parameter] = $parameterRule;
        return $this;
    }

    public function checkExist(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody() ?? [];
        $parameters = [];
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof RuleValidator) {
                if (!array_key_exists($key, $args) && $paramValidator->isRequired()) {
                    $parameters[] = $key . ' parameter is required';
                }
            } else {
                throw new \InvalidArgumentException('Value of ' . $key . ' must be a child instance of RuleValidator');
            }
        }
        if (!empty($parameters)) {
            $this->requiredErrors['parameters'] = $parameters;
        }
        return empty($this->requiredErrors);
    }

    public function validate(ServerRequestInterface $request): bool
    {
        $args = $request->getParsedBody() ?? [];
        foreach ($this->parametersValidator as $key => $paramValidator) {
            if ($paramValidator instanceof RuleValidator) {
                try {
                    if (array_key_exists($key, $args)) {
                        $paramValidator->getValidator()->setName($key)->assert($args[$key]);
                    }
                } catch (NestedValidationException $e) {
                    if (empty($paramValidator->getCustomMessages())) {
                        $this->validatorErrors[$key] = $e->getMessages();
                    } else {
                        $errors = [];
                        foreach (array_values($e->findMessages($paramValidator->getCustomMessages())) as $error) {
                            if ('' !== $error) {
                                $errors[] = $error;
                            }
                        }
                        $this->validatorErrors[$key] = $errors;
                    }
                }
            } else {
                throw new \InvalidArgumentException('Key : ' . $key . ' => ' . $paramValidator . ' must be an instance of RuleValidator');
            }
        }
        return empty($this->validatorErrors);
    }
}