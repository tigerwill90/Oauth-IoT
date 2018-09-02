<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 23:43
 */

namespace Oauth\Services\Validators;


use Oauth\Services\Validators\Rules\RuleValidator;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class QueryValidator extends Validator
{
    /**
     * <code>
     * $attributesValidator = [
     *      'client_id' => new ClientNameRule(true),
     *      'parameter' => RuleValidator
     * ]
     * @var array[string]RuleValidator
     */
    protected $queryValidator;

    public function __construct()
    {
    }

    /**
     * Add a new RuleValidator
     * @param string $query
     * @param RuleValidator $queryRule
     * @return Validator
     */
    public function add(string $query, RuleValidator $queryRule): Validator
    {
        $this->queryValidator[$query] = $queryRule;
        return $this;
    }

    public function checkExist(ServerRequestInterface $request): bool
    {
        $queryParams = $request->getQueryParams() ?? [];
        $queries = [];
        foreach ($this->queryValidator as $key => $qValidator) {
            if ($qValidator instanceof RuleValidator) {
                if (!array_key_exists($key, $queryParams) && $qValidator->isRequired()) {
                    $queries[] = $key . ' query parameter is required';
                }
            } else {
                throw new \InvalidArgumentException('Value of ' . $key . ' must be a child instance of RuleValidator');
            }
        }
        if (!empty($queries)) {
            $this->requiredErrors['query_parameter'] = $queries;
        }
        return empty($this->requiredErrors);
    }

    public function validate(ServerRequestInterface $request): bool
    {
        $queryParams = $request->getQueryParams() ?? [];
        foreach ($this->queryValidator as $key => $qValidator) {
            if ($qValidator instanceof RuleValidator) {
                try {
                    if (array_key_exists($key, $queryParams)) {
                        $qValidator->getValidator()->setName($key)->assert($queryParams[$key]);
                    }
                } catch (NestedValidationException $e) {
                    if (empty($qValidator->getCustomMessages())) {
                        $this->validatorErrors[$key] = $e->getMessages();
                    } else {
                        $errors = [];
                        foreach (array_values($e->findMessages($qValidator->getCustomMessages())) as $error) {
                            if ('' !== $error) {
                                $errors[] = $error;
                            }
                        }
                        $this->validatorErrors[$key] = $errors;
                    }
                }
            } else {
                throw new \InvalidArgumentException('Key : ' . $key . ' => ' . $qValidator . ' must be an instance of RuleValidator');
            }
        }
        return empty($this->validatorErrors);
    }
}