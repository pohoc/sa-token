<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use ReflectionClass;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaAnnotationProcessor
{
    public static function process(string $class, string $method): void
    {
        if (!class_exists($class)) {
            return;
        }
        $reflectionClass = new ReflectionClass($class);

        $targetMethod = $reflectionClass->hasMethod($method) ? $reflectionClass->getMethod($method) : null;
        $targetMethodDeclaration = $targetMethod?->getDeclaringClass()->getName();
        $targetMethodAttributes = $targetMethod?->getAttributes() ?? [];
        $interfaceAttributes = self::getInterfaceAuthorizationAttributes($reflectionClass, $method);
        $hasMoreSpecificAuthorization = self::hasAuthorizationAttribute($reflectionClass->getAttributes())
            || ($targetMethodDeclaration === $reflectionClass->getName()
                && self::hasAuthorizationAttribute($targetMethodAttributes))
            || $interfaceAttributes !== [];
        foreach ($targetMethodAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                // 当前类直接声明的 method-level ignore 是明确的 opt-out；
                // 继承来的 ignore 不能抵消子类新增的类级授权要求；接口上的授权
                // 是实现契约，具体类和方法都不能用 ignore 将其关闭。
                if ($interfaceAttributes === []
                    && ($targetMethodDeclaration === $reflectionClass->getName() || !$hasMoreSpecificAuthorization)) {
                    return;
                }
            }
        }

        // 类级注解必须沿继承链合并：开发者习惯把 #[SaCheckLogin] 标在
        // BaseController 上，getAttributes() 不含父类会让继承式鉴权整体静默失效
        $classAttributes = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            $attributes = $c->getAttributes();
            $hasIgnore = false;
            foreach ($attributes as $attr) {
                if ($attr->getName() === SaIgnore::class) {
                    $hasIgnore = true;
                    break;
                }
            }

            if ($hasIgnore) {
                // Concrete class opt-out remains authoritative. An inherited
                // opt-out cannot cancel a stricter class/method declaration
                // added by a subclass. Interface authorization is a contract
                // requirement and cannot be disabled by an implementing class.
                if ($interfaceAttributes === []
                    && ($c->getName() === $reflectionClass->getName() || !$hasMoreSpecificAuthorization)) {
                    return;
                }
                continue;
            }

            $classAttributes = array_merge($classAttributes, $attributes);
            if (self::hasAuthorizationAttribute($attributes)) {
                $hasMoreSpecificAuthorization = true;
            }
        }
        // 重写方法仍需保留基类方法上的鉴权约束；否则仅覆盖业务实现就会
        // 静默移除 #[SaCheckLogin]/权限注解。按声明类去重，避免未重写的方法重复读取。
        $methodAttributes = [];
        $seenMethodDeclarations = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            if (!$c->hasMethod($method)) {
                continue;
            }
            $reflectedMethod = $c->getMethod($method);
            $declaration = $reflectedMethod->getDeclaringClass()->getName();
            if (isset($seenMethodDeclarations[$declaration])) {
                continue;
            }
            $seenMethodDeclarations[$declaration] = true;
            $attributes = $reflectedMethod->getAttributes();
            if ($interfaceAttributes !== []
                || $declaration !== $targetMethodDeclaration
                || ($hasMoreSpecificAuthorization && $declaration !== $reflectionClass->getName())) {
                $attributes = array_values(array_filter(
                    $attributes,
                    static fn (\ReflectionAttribute $attribute): bool => $attribute->getName() !== SaIgnore::class
                ));
            }
            $methodAttributes = array_merge($methodAttributes, $attributes);
        }

        foreach ($methodAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        foreach ($classAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        $allAttributes = array_merge($classAttributes, $methodAttributes, $interfaceAttributes);

        self::processAuthorizationAttributes($allAttributes);
    }

    /** @param array<\ReflectionAttribute<object>> $attributes */
    protected static function processAuthorizationAttributes(array $attributes): void
    {
        foreach ($attributes as $attr) {
            $instance = $attr->newInstance();
            $loginType = method_exists($instance, 'getLoginType') ? $instance->getLoginType() : 'login';
            if (!is_string($loginType)) {
                $loginType = 'login';
            }
            $stpLogic = SaToken::getStpLogic($loginType);

            if ($instance instanceof SaCheckLogin) {
                $stpLogic->checkLogin();
            } elseif ($instance instanceof SaCheckPermission) {
                $permissions = self::parseAuthorizationValues($instance->getValue(), '权限');
                if (self::normalizeAuthorizationMode($instance->getMode(), '权限') === 'AND') {
                    $stpLogic->checkPermissionAnd($permissions);
                } else {
                    $stpLogic->checkPermissionOr($permissions);
                }
            } elseif ($instance instanceof SaCheckRole) {
                $roles = self::parseAuthorizationValues($instance->getValue(), '角色');
                if (self::normalizeAuthorizationMode($instance->getMode(), '角色') === 'AND') {
                    $stpLogic->checkRoleAnd($roles);
                } else {
                    $stpLogic->checkRoleOr($roles);
                }
            } elseif ($instance instanceof SaCheckSafe) {
                $service = $instance->getService();
                // OTP verification state is account-scoped, while safe windows
                // are bound to the current token. Treating a verified account as
                // a safe token lets a second device skip its own re-verification.
                $stpLogic->checkSafe($service);
            } elseif ($instance instanceof SaCheckDisable) {
                $loginId = $stpLogic->getLoginId();
                if ($loginId !== null) {
                    $stpLogic->checkDisable($loginId, $instance->getService());
                }
            }
        }
    }

    /** @return array<string> */
    protected static function parseAuthorizationValues(string $value, string $kind): array
    {
        $values = array_map('trim', explode(',', $value));
        if ($values === [] || in_array('', $values, true)) {
            throw new SaTokenException("{$kind}注解必须包含非空值，且不能有空白项");
        }

        return $values;
    }

    protected static function normalizeAuthorizationMode(string $mode, string $kind): string
    {
        $normalized = strtoupper(trim($mode));
        if (!in_array($normalized, ['AND', 'OR'], true)) {
            throw new SaTokenException("{$kind}注解 mode 只支持 AND 或 OR");
        }

        return $normalized;
    }

    /** @param array<\ReflectionAttribute<object>> $attributes */
    protected static function hasAuthorizationAttribute(array $attributes): bool
    {
        foreach ($attributes as $attribute) {
            if (in_array($attribute->getName(), [
                SaCheckLogin::class,
                SaCheckPermission::class,
                SaCheckRole::class,
                SaCheckSafe::class,
                SaCheckDisable::class,
            ], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Interface authorization attributes are contract requirements. Interface
     * SaIgnore attributes are deliberately excluded so an implemented
     * interface cannot opt a controller out of class or method authorization.
     *
     * @param  ReflectionClass<object>             $class
     * @return array<\ReflectionAttribute<object>>
     */
    protected static function getInterfaceAuthorizationAttributes(ReflectionClass $class, string $method): array
    {
        $result = [];
        $seenMethodDeclarations = [];
        foreach ($class->getInterfaces() as $interface) {
            foreach ($interface->getAttributes() as $attribute) {
                if (self::hasAuthorizationAttribute([$attribute])) {
                    $result[] = $attribute;
                }
            }

            if (!$interface->hasMethod($method)) {
                continue;
            }
            $interfaceMethod = $interface->getMethod($method);
            $declaration = $interfaceMethod->getDeclaringClass()->getName();
            if (isset($seenMethodDeclarations[$declaration])) {
                continue;
            }
            $seenMethodDeclarations[$declaration] = true;
            foreach ($interfaceMethod->getAttributes() as $attribute) {
                if (self::hasAuthorizationAttribute([$attribute])) {
                    $result[] = $attribute;
                }
            }
        }

        return $result;
    }

    public static function processCallable(callable $callable): void
    {
        if (is_array($callable) && count($callable) === 2) {
            $class = is_object($callable[0]) ? $callable[0]::class : $callable[0];
            self::process($class, $callable[1]);
            return;
        }

        if (is_string($callable) && str_contains($callable, '::')) {
            [$class, $method] = explode('::', $callable, 2);
            self::process($class, $method);
            return;
        }

        if ($callable instanceof \Closure || is_string($callable)) {
            self::processFunction($callable);
            return;
        }

        if (is_object($callable)) {
            self::process($callable::class, '__invoke');
        }
    }

    protected static function processFunction(string|\Closure $function): void
    {
        $attributes = (new \ReflectionFunction($function))->getAttributes();
        foreach ($attributes as $attribute) {
            if ($attribute->getName() === SaIgnore::class) {
                return;
            }
        }

        self::processAuthorizationAttributes($attributes);
    }

    /**
     * @return array<object>
     */
    public static function getMethodAttributes(string $class, string $method): array
    {
        if (!class_exists($class)) {
            return [];
        }
        $reflectionClass = new ReflectionClass($class);

        $result = [];
        $classAttrs = [];
        $methodAttrs = [];
        $seenMethodDeclarations = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            $classAttrs = array_merge($classAttrs, $c->getAttributes());
            if (!$c->hasMethod($method)) {
                continue;
            }
            $reflectedMethod = $c->getMethod($method);
            $declaration = $reflectedMethod->getDeclaringClass()->getName();
            if (isset($seenMethodDeclarations[$declaration])) {
                continue;
            }
            $seenMethodDeclarations[$declaration] = true;
            $methodAttrs = array_merge($methodAttrs, $reflectedMethod->getAttributes());
        }

        $methodAttrs = array_merge($methodAttrs, self::getInterfaceAuthorizationAttributes($reflectionClass, $method));

        foreach (array_merge($classAttrs, $methodAttrs) as $attr) {
            if (str_starts_with($attr->getName(), 'SaToken\\Annotation\\')) {
                $result[] = $attr->newInstance();
            }
        }

        return $result;
    }
}
