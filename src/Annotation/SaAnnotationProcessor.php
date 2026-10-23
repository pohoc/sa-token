<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use ReflectionClass;
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
        $hasMoreSpecificAuthorization = self::hasAuthorizationAttribute($reflectionClass->getAttributes())
            || ($targetMethodDeclaration === $reflectionClass->getName()
                && self::hasAuthorizationAttribute($targetMethodAttributes));
        foreach ($targetMethodAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                // 当前类直接声明的 method-level ignore 是明确的 opt-out；
                // 继承来的 ignore 不能抵消子类新增的类级授权要求。
                if ($targetMethodDeclaration === $reflectionClass->getName() || !$hasMoreSpecificAuthorization) {
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
                // added by a subclass.
                if ($c->getName() === $reflectionClass->getName() || !$hasMoreSpecificAuthorization) {
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
            if ($declaration !== $targetMethodDeclaration
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

        $allAttributes = array_merge($classAttributes, $methodAttributes);

        foreach ($allAttributes as $attr) {
            $instance = $attr->newInstance();
            $loginType = method_exists($instance, 'getLoginType') ? $instance->getLoginType() : 'login';
            if (!is_string($loginType)) {
                $loginType = 'login';
            }
            $stpLogic = SaToken::getStpLogic($loginType);

            if ($instance instanceof SaCheckLogin) {
                $stpLogic->checkLogin();
            } elseif ($instance instanceof SaCheckPermission) {
                $permissions = explode(',', $instance->getValue());
                $permissions = array_map('trim', $permissions);
                if (strtoupper($instance->getMode()) === 'AND') {
                    $stpLogic->checkPermissionAnd($permissions);
                } else {
                    $stpLogic->checkPermissionOr($permissions);
                }
            } elseif ($instance instanceof SaCheckRole) {
                $roles = explode(',', $instance->getValue());
                $roles = array_map('trim', $roles);
                if (strtoupper($instance->getMode()) === 'AND') {
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

    public static function processCallable(callable $callable): void
    {
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

        foreach (array_merge($classAttrs, $methodAttrs) as $attr) {
            if (str_starts_with($attr->getName(), 'SaToken\\Annotation\\')) {
                $result[] = $attr->newInstance();
            }
        }

        return $result;
    }
}
